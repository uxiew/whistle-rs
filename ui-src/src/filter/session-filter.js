// The capture list's search box — whistle's little filter language.
//
// `gui/network.md` documents it: a bare keyword matches the URL, and a prefix
// asks about something else — `m:` the method, `s:` the status, `t:` the content
// type, and so on. Every condition takes a **keyword or a `/regexp/flags`**, and
// several conditions separated by spaces are AND-ed:
//
//     b:"success":false m:POST s:200 H:api.example.com
//
// This console used to match a bare substring against four fields and ignore any
// prefix, which meant `m:POST` looked for the *text* `m:POST` in the URL and
// found nothing. A filter that silently matches nothing is the same trap as a
// rule that silently does nothing, so the four conditions this console cannot
// answer are **reported** rather than quietly dropped — see `UNSUPPORTED`.
//
// ── why this file is plain script-shaped JavaScript ────────────────────────
// The same reason as `editor/whistle-classify.js`: it is bundled into the
// console by Vite *and* evaluated as a bare script by a Rust test, which runs it
// in the JS engine the proxy already carries and holds its answers against a
// table of cases. One copy, so the two cannot drift. No `import`/`export`; the
// entry points are hung on `globalThis` at the bottom.

'use strict';

/**
 * What each prefix asks about, and where the answer lives on a summary row.
 *
 * The list rows carry no headers and no bodies — those are fetched per request,
 * and carrying them for every row is what the summary exists to avoid — so the
 * conditions that need them are not here. They are named in `UNSUPPORTED`, where
 * a person can be told rather than left with an empty list.
 */
const FIELDS = {
  // The default: the whole URL.
  '': (s) => s.url || '',
  m: (s) => s.method || '',
  // The host, which the URL already carries — no extra field needed.
  H: (s) => {
    const url = s.url || '';
    const at = url.indexOf('://');
    const rest = at === -1 ? url : url.slice(at + 3);
    const end = rest.search(/[/?#]/);
    return end === -1 ? rest : rest.slice(0, end);
  },
  s: (s) => String(s.status == null ? '' : s.status),
  // "The client IP or the server's" — both, so either answers.
  i: (s) => [s.client_ip || '', s.target || ''].join(' '),
  t: (s) => s.type || '',
  // `style://` is not a traffic operator; its whole purpose is to colour a row,
  // so filtering on it is what it is for.
  style: (s) => (s.rules || [])
    .filter((r) => r.protocol === 'style')
    .map((r) => r.value)
    .join(' '),
};

/**
 * Conditions that need a per-row fact this console does not keep.
 *
 * Each one is a sentence rather than a flag, because the point is to say *why*:
 * a person who types `b:` deserves to know the bodies are not in the list rather
 * than to conclude their body does not contain what they know it contains.
 */
const UNSUPPORTED = {
  h: 'the raw headers are fetched per request, not carried on every row',
  b: 'the bodies are fetched per request, not carried on every row',
  app: 'this console does not know which application a request came from',
  fc: 'requests sent from the Composer are not marked as such yet',
};

/** `/…/flags` is a regexp; anything else is a case-insensitive substring. */
function toTest(value) {
  const re = /^\/(.*)\/([a-z]*)$/.exec(value);
  if (re) {
    try {
      const rx = new RegExp(re[1], re[2]);
      return (text) => rx.test(text);
    } catch (e) {
      // An unfinished regexp is what a half-typed one looks like. Matching
      // nothing while it is being typed is better than throwing at every
      // keystroke, and it comes right as soon as the expression closes.
      return () => false;
    }
  }
  const needle = value.toLowerCase();
  return (text) => text.toLowerCase().includes(needle);
}

/**
 * Split a query into conditions.
 *
 * Space-separated, except inside a `/regexp/` — `b:/a b/` is one condition and
 * not two, which is the only place the split has to be careful.
 */
function split(query) {
  const out = [];
  let buf = '';
  let inRegex = false;
  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    if (ch === '/' && query[i - 1] !== '\\') {
      // A `/` opens a regexp only where a value starts.
      if (!inRegex && /(^|:)$/.test(buf)) inRegex = true;
      else if (inRegex) inRegex = false;
    }
    if (ch === ' ' && !inRegex) {
      if (buf) out.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf) out.push(buf);
  return out;
}

/**
 * Parse a query into `{ conditions, unsupported }`.
 *
 * A prefix is only a prefix when it is one this console knows: `s:404` asks
 * about the status, and `http://a/b:c` is a URL that happens to contain a colon
 * and stays one.
 */
function parseFilter(query) {
  const conditions = [];
  const unsupported = [];
  for (const piece of split(String(query || '').trim())) {
    const at = piece.indexOf(':');
    const prefix = at === -1 ? null : piece.slice(0, at);
    const value = at === -1 ? piece : piece.slice(at + 1);
    if (prefix !== null && Object.prototype.hasOwnProperty.call(UNSUPPORTED, prefix)) {
      if (!unsupported.some((u) => u.prefix === prefix)) {
        unsupported.push({ prefix, why: UNSUPPORTED[prefix] });
      }
      continue;
    }
    const known = prefix !== null && Object.prototype.hasOwnProperty.call(FIELDS, prefix) && prefix !== '';
    // Two prefixes are a *set* as much as a pattern, so an empty value means
    // the set itself: `mark:` is "the ones I marked" and `e:` is "the ones that
    // went wrong". Without this, `toTest('')` matches every string — including
    // the empty one a row that did *not* go wrong reports — and `e:` on its own
    // would quietly select everything, which is the opposite of what it says.
    if (prefix === 'mark' || prefix === 'e') {
      const test = value ? toTest(value) : (text) => text !== '';
      conditions.push({ field: prefix, test });
      continue;
    }
    if (known && !value) continue; // `m:` with nothing after it asks nothing.
    conditions.push({ field: known ? prefix : '', test: toTest(known ? value : piece) });
  }
  return { conditions, unsupported };
}

/**
 * Does this row satisfy every condition?
 *
 * `ctx.marked` is the set of ids the console has marked by hand, which is the
 * one condition whose answer is not on the row.
 */
function matchSession(session, conditions, ctx) {
  const marked = (ctx && ctx.marked) || [];
  for (const c of conditions) {
    let text;
    if (c.field === 'mark') {
      text = marked.includes(session.id) ? (session.url || '') : '';
    } else if (c.field === 'e') {
      const failed = !session.status || session.status >= 400;
      text = failed ? [session.url || '', String(session.status || 0)].join(' ') : '';
    } else {
      text = FIELDS[c.field](session);
    }
    if (!c.test(text)) return false;
  }
  return true;
}

globalThis.whistleParseFilter = parseFilter;
globalThis.whistleMatchSession = matchSession;
