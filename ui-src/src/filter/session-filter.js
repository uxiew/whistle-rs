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
// rule that silently does nothing, so a condition this console cannot answer is
// **reported** rather than quietly dropped — see `UNSUPPORTED`. `h:` and `b:`
// read what a row does not carry, and the proxy answers them — see `REMOTE`.
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
 * conditions that need them are not here but in `REMOTE`.
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
 * Conditions the proxy answers, because a row does not carry what they read.
 *
 * The headers and bodies are not on a summary row, so the search box sends
 * these to `/api/sessions/search` and passes the answer back in as
 * `ctx.remote`: the ids that matched, keyed by the condition as written.
 */
const REMOTE = { h: true, b: true };

/**
 * Conditions this console cannot answer at all.
 *
 * Each one is a sentence rather than a flag, because the point is to say *why*:
 * a person who types `app:` deserves to know the console cannot tell rather
 * than to conclude no request came from the app they know sent some.
 */
const UNSUPPORTED = {
  // Upstream guesses it in the browser from the User-Agent; a guess presented
  // as a fact about the traffic is worse than no answer.
  app: 'this console does not know which application a request came from',
};

/**
 * Why the capture filters take no `h:`/`b:`: they decide on a row as it
 * arrives, from the row, and the answer to these comes from the proxy later.
 */
const NOT_ON_ARRIVAL =
  'the capture filters decide on a row as it arrives, from the row alone; search headers and bodies from the search box';

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
 * Space-separated, except that a `/regexp/` may contain spaces: `b:/a b/` is one
 * condition and not two. The care is in telling that from a **path**, which is
 * the most natural thing to type here and also starts with a slash —
 * `/heartbeat m:POST` is two conditions, and an earlier version of this read it
 * as one unterminated regexp and therefore matched nothing at all.
 *
 * So a slash only opens a regexp when the token it starts does not already
 * close one, and the joining stops at the first token that does. A `/…` that
 * never closes is left as the plain text it looks like.
 */
function split(query) {
  const words = String(query).split(/\s+/).filter(Boolean);
  const out = [];
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const at = word.indexOf(':');
    const value = at === -1 ? word : word.slice(at + 1);
    // Already a closed regexp, or not one at all.
    if (value[0] !== '/' || /^\/.*\/[a-z]*$/.test(value)) {
      out.push(word);
      continue;
    }
    // Open: join words until one closes it. If none does, this was a path.
    let joined = word;
    let closed = false;
    for (let j = i + 1; j < words.length; j++) {
      joined += ' ' + words[j];
      if (/\/[a-z]*$/.test(words[j])) {
        i = j;
        closed = true;
        break;
      }
    }
    out.push(closed ? joined : word);
  }
  return out;
}

/**
 * Parse a query into `{ conditions, unsupported }`.
 *
 * A prefix is only a prefix when it is one this console knows: `s:404` asks
 * about the status, and `http://a/b:c` is a URL that happens to contain a colon
 * and stays one.
 *
 * `opts.remote` says the caller will ask the proxy about `h:`/`b:` — the search
 * box does. A condition that needs the proxy carries `remote: true` and the
 * `key` its answer is filed under. Without it, as in the capture filters, the
 * two are reported like any other condition that cannot be answered.
 */
function parseFilter(query, opts) {
  const remote = !!(opts && opts.remote);
  const conditions = [];
  const unsupported = [];
  const report = (prefix, why) => {
    if (!unsupported.some((u) => u.prefix === prefix)) unsupported.push({ prefix, why });
  };
  for (const piece of split(String(query || '').trim())) {
    const at = piece.indexOf(':');
    const prefix = at === -1 ? null : piece.slice(0, at);
    const value = at === -1 ? piece : piece.slice(at + 1);
    if (prefix !== null && Object.prototype.hasOwnProperty.call(UNSUPPORTED, prefix)) {
      report(prefix, UNSUPPORTED[prefix]);
      continue;
    }
    if (prefix !== null && Object.prototype.hasOwnProperty.call(REMOTE, prefix)) {
      if (!remote) report(prefix, NOT_ON_ARRIVAL);
      // `h:` with nothing after it asks nothing, like `m:`.
      else if (value) conditions.push({ field: prefix, remote: true, key: piece });
      continue;
    }
    const known = prefix !== null && Object.prototype.hasOwnProperty.call(FIELDS, prefix) && prefix !== '';
    // Some prefixes are a *set* as much as a pattern, so an empty value means
    // the set itself: `mark:` is "the ones I marked", `e:` "the ones that went
    // wrong" and `fc:` "the ones the Composer sent". Without this, `toTest('')`
    // matches every string — including the empty one a row that did *not* go
    // wrong reports — and `e:` on its own would quietly select everything,
    // which is the opposite of what it says.
    if (prefix === 'mark' || prefix === 'e' || prefix === 'fc') {
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
 * Two answers are not on the row: `ctx.marked` is the ids the console has
 * marked by hand, and `ctx.remote` maps a remote condition's `key` to the ids
 * the proxy said match it (an array or a `Set`). A remote condition with no
 * answer yet matches nothing — the caller says it is still asking.
 */
function matchSession(session, conditions, ctx) {
  const marked = (ctx && ctx.marked) || [];
  const answers = (ctx && ctx.remote) || {};
  for (const c of conditions) {
    if (c.remote) {
      const ids = answers[c.key];
      const hit = ids && (typeof ids.has === 'function' ? ids.has(session.id) : ids.includes(session.id));
      if (!hit) return false;
      continue;
    }
    let text;
    if (c.field === 'fc') {
      // Sent from the Composer or Replay — and, with a value, to a URL that
      // matches it: upstream's `fc:` is that same pair
      // (`network-modal.js:236-238`).
      text = session.composer ? (session.url || '') : '';
    } else if (c.field === 'mark') {
      text = marked.includes(session.id) ? (session.url || '') : '';
    } else if (c.field === 'e') {
      // Gone wrong: the proxy recorded why it did not complete, or the answer
      // was an error status — or no answer at all, in history written before
      // failures were recorded. The phase and the reason are searchable, so
      // `e:dns` finds the names that did not resolve.
      const failure = session.error;
      const failed = !!failure || !session.status || session.status >= 400;
      text = failed
        ? [
          session.url || '',
          String(session.status || 0),
          failure ? failure.phase : '',
          failure ? failure.message : '',
        ].join(' ')
        : '';
    } else {
      text = FIELDS[c.field](session);
    }
    if (!c.test(text)) return false;
  }
  return true;
}

/**
 * Does this row satisfy **any** condition?
 *
 * The capture filters read this way where the search box reads `matchSession`:
 * `gui/network.md` says conditions inside one box are OR-ed and the two boxes
 * are AND-ed, which is the opposite grouping from the search box's single
 * AND-ed line. Same conditions, same parser, different join.
 */
function matchAny(session, conditions, ctx) {
  return conditions.some((c) => matchSession(session, [c], ctx));
}

globalThis.whistleMatchAny = matchAny;
globalThis.whistleParseFilter = parseFilter;
globalThis.whistleMatchSession = matchSession;
