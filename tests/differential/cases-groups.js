// Rule **groups**: several rules texts at once, their order, their switches,
// and what one group can see of another.
//
//   PORT_BASE=19700 node oracle.js &
//   cargo run -- --port 19701 --no-persist --dir /tmp/rs-groups &
//   PORT_BASE=19700 CASES=./cases-groups.js npm run bench
//
// **Why this corpus exists.** Every other file here runs inside one group
// called `Default`, because that is all `setRules` could set: one text, through
// each proxy's own endpoint. Eleven corpora and some 1600 cases said nothing
// about a second group — not its order, not its switch, not what happens when
// it is deleted. A precedence bug lived in that blind spot and was found by a
// standalone script rather than by the bench: this port resolved the default
// group **first**, so a named group could never override it, where upstream
// appends `Default` last (`_original/lib/rules/util.js:94-101`). The harness
// now takes `groups: [{ name, value, selected? }]`, and this file is the
// question the corpus could not previously ask.
//
// **What a group is on each side.** Upstream has a list of *rule files*, each
// selected or not, plus a `Default` text that is not a file and is always
// resolved last. This port has a list of *rule groups*, each enabled or not,
// one of which is named `default` and is likewise resolved last
// (`RuleManager::resolution_order`). The harness maps one onto the other:
// `/cgi-bin/rules/add` + `/cgi-bin/rules/select` against `POST /api/rule-groups`.
//
// **Upstream selects one file at a time** unless `allowMultipleChoice` is on
// (`selectRulesFile`, `_original/lib/rules/util.js:148-161`), so the harness
// pins that property on before the corpus. Without it every case below would
// have exactly one group and would measure nothing.
//
// **State between cases.** A rule group outlives the case that made it, on both
// sides, and both proxies persist theirs. The harness deletes every named group
// before a corpus and after any case that installed one; `an empty slate` at
// the top of this file is the case that proves it, by asserting that the group
// the case above it installed is gone.
//
// ── Cases expected to differ ───────────────────────────────────────────────
//
// A clean run of this file is **`differing: 4`**, from two causes, both named
// here.
//
//  1. `two groups with the same name` — upstream's `add` is a file write, so the
//     second text **replaces** the first (`rules.add` → `rulesStorage.writeFile`,
//     `_original/biz/webui/cgi-bin/rules/add.js:13`, and `storage.js:260-283`).
//     This port's `add_group` refuses a name it already has and answers
//     `400 group already exists`, keeping the first text; changing a group's
//     text is `POST /api/rule-group/update`, which upstream has no separate
//     endpoint for. Two API shapes rather than two behaviours — every text the
//     other API can reach, this one can reach too — and the shape that refuses
//     to overwrite silently is the better of them. Declared, not aligned.
//
//  2. The three `values block` cases — upstream files an inline ``` block under
//     a key **private to the rules file that declared it** (`getInlineKey` =
//     `key + '\n\r' + file`, `_original/lib/util/index.js:205-209`), and
//     `getValueFor` looks that private key up before falling back to the
//     **stored** values (`_original/lib/rules/rules.js:785-796`) — never to
//     another file's inline map. So upstream's second group sees nothing and
//     `resBody://{v}` never fires, in either direction, and a second block of
//     the same name cannot shadow the first group's own. This port merges every
//     enabled group's blocks into one flat map (`RuleManager::inline_values` →
//     `effective_values`, `src/proxy/mod.rs:2810`), so all three fire.
//     Reported, not fixed: scoping it means carrying the declaring group down
//     into the resolved operator set, which is the values resolution path
//     rather than this one.
//
// ── How much of this measures anything ─────────────────────────────────────
//
// **41 of the 51 cases change something on the real-whistle side**, and 43 do
// here — the two extra being two of the values cases above, which is the
// divergence and not an accident. Measured the only way that means anything:
// each case's setup run twice per proxy, once with its groups and once with
// none, and the two answers compared. A group that never applied and a group
// that applied and changed nothing are the same picture.
//
// Eight of the ten inert ones are where *nothing happening* is the fact under
// test: the empty slate, an unselected group on its own, every group
// unselected, an empty group on its own, a comment-only group on its own, a
// deleted group on its own, Default switched off, and an unselected group whose
// `@` include must not be applied. The other two are the two values cases where
// upstream doing nothing **is** the divergence.
//
// ── What this file discriminates against ───────────────────────────────────
//
// Run against the build with the precedence fix reverted — the default group
// resolved first, which is what this port did until it was measured — this file
// reports **`differing: 9`**: the four above plus five that no other corpus can
// reach, `a named group overrides Default`, `Default written first is still
// resolved last`, `two named groups and Default`, `important in a named group
// outranks an important in Default`, and `an include in a named group outranks
// Default`.
//
// Run against the build from before `remove_group` learned to refuse the
// default group, it reports **`differing: 5`** — the fifth being `deleting the
// Default group is refused`.

const fs = require('fs');
const path = require('path');

const BASE = Number(process.env.PORT_BASE || 18700);
const P = `127.0.0.1:${BASE + 2}`;
/** `A` pins the pattern to the whole path — the trap `cases-file.js` documents. */
const A = `${P}/echo`;

/** A fence, spelled once so the cases below stay readable. */
const B = '```';

// ── include sources ────────────────────────────────────────────────────────
// One file per case that needs its own content, for the reason
// `cases-includes.js` gives: both proxies cache an include by its source
// string, so two cases sharing a path and disagreeing about it would be a race.

const DIR = '/tmp/wrs-groups-fixtures';
const F = (name) => path.join(DIR, name);
const FILES = {
  'grp-inc.rules': `${A} reqHeaders://x-included=yes\n`,
  'grp-inc-method.rules': `${A} method://DELETE\n`,
  'grp-inc-off.rules': `${A} reqHeaders://x-from-an-off-group=yes\n`,
  'grp-inc-value.rules': `${B}iv\nFROM-AN-INCLUDE\n${B}\n`,
};
fs.mkdirSync(DIR, { recursive: true });
for (const [name, text] of Object.entries(FILES)) fs.writeFileSync(F(name), text);

module.exports = [
  // ── the slate ──────────────────────────────────────────────────────────
  // First, that a group applies at all — everything below is unreadable
  // without it. Second, that the group the first case installed is *gone*:
  // a probe that leaks state between cases reports divergences it invented.
  { name: 'a named group applies', groups: [{ name: 'A', value: `${A} reqHeaders://x-a=yes` }] },
  { name: 'an empty slate', rules: '' },

  // ── order and precedence ───────────────────────────────────────────────
  // `method://` is single-valued, so the echo's method names the line that
  // won outright — no merging to read through.
  {
    name: 'of two groups the earlier one wins',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // The same two texts the other way round. Discriminates against a fixed
    // order — alphabetical, or last-added-first — which the case above cannot.
    name: 'the same two groups in the other order',
    groups: [
      { name: 'B', value: `${A} method://DELETE` },
      { name: 'A', value: `${A} method://PUT` },
    ],
  },
  {
    // The bug this corpus was written for. Discriminates against Default
    // resolving first, which is what this port used to do.
    name: 'a named group overrides Default',
    rules: `${A} method://PUT`,
    groups: [{ name: 'A', value: `${A} method://DELETE` }],
  },
  {
    // And with the two written the other way round in the case, to show the
    // order of the *declaration* is not what decides it: Default is last
    // because it is Default.
    name: 'Default written first is still resolved last',
    groups: [
      { name: 'Default', value: `${A} method://PUT` },
      { name: 'A', value: `${A} method://DELETE` },
    ],
  },
  {
    name: 'two named groups and Default: the first named one wins',
    rules: `${A} method://PATCH`,
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // Precedence is per operator, not per group: Default still supplies what no
    // named group said. Discriminates against "a named group replaces Default".
    name: 'Default supplies what no named group says',
    rules: `${A} reqHeaders://x-d=yes`,
    groups: [{ name: 'A', value: `${A} reqHeaders://x-a=yes` }],
  },
  {
    name: 'three groups contest one operator and the first wins',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
      { name: 'C', value: `${A} method://PATCH` },
    ],
  },
  {
    // Within one group the first line wins; the question is whether a *second*
    // group's first line outranks the first group's second line. It must not.
    name: 'a later group loses to a later line of an earlier group',
    groups: [
      { name: 'A', value: `${A} reqHeaders://x-only-a=yes\n${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // Two groups both merging into the same multi-valued operator. The contest
    // is per header name, so `x-a` and `x-b` both survive and `x-both` is the
    // earlier group's.
    name: 'two groups merge one multi-valued operator',
    groups: [
      { name: 'A', value: `${A} reqHeaders://x-a=yes&x-both=from-a` },
      { name: 'B', value: `${A} reqHeaders://x-b=yes&x-both=from-b` },
    ],
  },
  {
    // A response-phase operator, to show the ordering is not a request-pass
    // accident: both passes walk the groups in the same order.
    name: 'group order decides a response operator too',
    groups: [
      { name: 'A', value: `${A} resHeaders://x-r=from-a` },
      { name: 'B', value: `${A} resHeaders://x-r=from-b` },
    ],
  },
  {
    name: 'group order decides which body is served',
    groups: [
      { name: 'A', value: `${A} resBody://(FROM-A)` },
      { name: 'B', value: `${A} resBody://(FROM-B)` },
    ],
  },

  // ── lineProps://important across groups ────────────────────────────────
  {
    // `important` has to reach across the group boundary, or it means only
    // "important within my own file".
    name: 'important in the later group outranks the earlier group',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE lineProps://important` },
    ],
  },
  {
    name: 'important in the earlier group changes nothing',
    groups: [
      { name: 'A', value: `${A} method://PUT lineProps://important` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // Two importants fall back to group order. Discriminates against
    // "the last important wins".
    name: 'two importants in two groups: the earlier group wins',
    groups: [
      { name: 'A', value: `${A} method://PUT lineProps://important` },
      { name: 'B', value: `${A} method://DELETE lineProps://important` },
    ],
  },
  {
    // Default is resolved last, so this is the strongest form of the question:
    // an `important` on the *lowest-priority* text must still outrank a named
    // group that has none.
    name: 'important in Default outranks a named group',
    rules: `${A} method://PATCH lineProps://important`,
    groups: [{ name: 'A', value: `${A} method://PUT` }],
  },
  {
    name: 'important in a named group outranks an important in Default',
    rules: `${A} method://PATCH lineProps://important`,
    groups: [{ name: 'A', value: `${A} method://PUT lineProps://important` }],
  },

  // ── the selected / unselected distinction ──────────────────────────────
  {
    // On its own, so the answer is "nothing happened" and not "something else
    // happened". Paired with the case below, which makes it discriminate.
    name: 'an unselected group does not apply',
    groups: [{ name: 'A', value: `${A} method://PUT`, selected: false }],
  },
  {
    name: 'an unselected group does not win a contest it would have won',
    groups: [
      { name: 'A', value: `${A} method://PUT`, selected: false },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // An unselected group must not even carry its `important` into the contest.
    name: 'an unselected important is not important',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE lineProps://important`, selected: false },
    ],
  },
  {
    name: 'an unselected group does not shift the order of the rest',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE`, selected: false },
      { name: 'C', value: `${A} method://PATCH` },
    ],
  },
  {
    name: 'an unselected group does not hide Default',
    rules: `${A} method://PATCH`,
    groups: [{ name: 'A', value: `${A} method://PUT`, selected: false }],
  },
  {
    // Both switched off: everything falls through to the origin untouched.
    name: 'every group unselected leaves the request alone',
    groups: [
      { name: 'A', value: `${A} method://PUT`, selected: false },
      { name: 'B', value: `${A} reqHeaders://x-b=yes`, selected: false },
    ],
  },

  // ── groups with nothing in them ────────────────────────────────────────
  {
    name: 'an empty group on its own changes nothing',
    groups: [{ name: 'A', value: '' }],
  },
  {
    // An empty group must not consume a slot in the ordering: `C` still loses
    // to `A`, and `B` being empty does not promote it.
    name: 'an empty group between two others keeps the order',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: '' },
      { name: 'C', value: `${A} method://PATCH` },
    ],
  },
  {
    // Upstream drops a group whose text is falsy before it ever reaches the
    // list (`if (text)` in `addRules`), so an empty *first* group is the case
    // where a naive port would still put it in front.
    name: 'an empty first group does not outrank a full second one',
    groups: [
      { name: 'A', value: '' },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    name: 'a group of nothing but a comment changes nothing',
    groups: [{ name: 'A', value: '# nothing but a comment' }],
  },
  {
    // A comment-only group is *not* empty text, so it takes the `addRules` path
    // an empty one does not, and still must not shift precedence.
    name: 'a comment-only first group does not outrank the second',
    groups: [
      { name: 'A', value: '# nothing but a comment' },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    name: 'a group of whitespace changes nothing',
    groups: [
      { name: 'A', value: '   \n\t\n  ' },
      { name: 'B', value: `${A} method://DELETE` },
    ],
  },
  {
    // Declared as a divergence at the top of this file: upstream overwrites the
    // file, this port refuses the second add and keeps the first text.
    name: 'two groups with the same name',
    groups: [
      { name: 'dup', value: `${A} method://PUT` },
      { name: 'dup', value: `${A} method://DELETE` },
    ],
  },

  // ── deleting a group mid-session ───────────────────────────────────────
  // `remove` runs after the groups are installed, so these ask what a deletion
  // does — not what never adding the group would have done. A port that files
  // the parsed rules somewhere the delete does not reach answers the same as if
  // the group were still there.
  {
    name: 'a deleted group stops applying',
    groups: [{ name: 'A', value: `${A} method://PUT` }],
    remove: ['A'],
  },
  {
    name: 'deleting the winner lets the next group win',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
    remove: ['A'],
  },
  {
    name: 'deleting the loser leaves the winner alone',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} method://DELETE` },
    ],
    remove: ['B'],
  },
  {
    name: 'deleting a group leaves the other headers alone',
    groups: [
      { name: 'A', value: `${A} reqHeaders://x-a=yes` },
      { name: 'B', value: `${A} reqHeaders://x-b=yes` },
    ],
    remove: ['A'],
  },
  {
    name: 'deleting the only named group falls back to Default',
    rules: `${A} method://PATCH`,
    groups: [{ name: 'A', value: `${A} method://PUT` }],
    remove: ['A'],
  },
  {
    name: 'deleting a group that is not there changes nothing',
    groups: [{ name: 'A', value: `${A} method://PUT` }],
    remove: ['nosuch'],
  },
  {
    // Re-adding under the same name after a delete has to give the *new* text,
    // which is the one shape `two groups with the same name` cannot ask about.
    name: 'a group re-added after a delete carries the new text',
    groups: [
      { name: 'A', value: `${A} method://PUT` },
      { name: 'B', value: `${A} reqHeaders://x-b=yes` },
    ],
    remove: ['A'],
  },
  {
    // Upstream's Default is a property and not a file, so its remove endpoint
    // deletes nothing and the rules stay. This port used to delete the group —
    // and with it the text `GET`/`POST /api/rules` reads and writes — then
    // persist the loss. See `RuleManager::remove_group`.
    name: 'deleting the Default group is refused',
    rules: `${A} method://PUT`,
    remove: ['Default'],
  },

  // ── the Default group's own switch ─────────────────────────────────────
  // Upstream sets it outright (`enable-default` / `disable-default`); this port
  // toggles the group called `default`. Both reach the same two states.
  {
    name: 'Default switched off does not apply',
    groups: [{ name: 'Default', value: `${A} method://PUT`, selected: false }],
  },
  {
    // The proof that the harness put the switch back: this case follows one
    // that turned it off, and says nothing else.
    name: 'Default applies again once the switch is back',
    rules: `${A} method://PUT`,
  },
  {
    name: 'Default switched off leaves a named group applying',
    groups: [
      { name: 'Default', value: `${A} method://PUT`, selected: false },
      { name: 'A', value: `${A} reqHeaders://x-a=yes` },
    ],
  },
  {
    // With Default off, the named group's line is the only one left and wins
    // outright — the contest it would have lost is not merely re-decided, it is
    // gone.
    name: 'Default switched off stops it contesting an operator',
    groups: [
      { name: 'Default', value: `${A} method://PUT lineProps://important`, selected: false },
      { name: 'A', value: `${A} method://DELETE` },
    ],
  },

  // ── one group's text seen from another ─────────────────────────────────
  // `resBody://{v}` and not `reqHeaders://x-v={v}`: an inline block's value
  // ends in a newline, so a header built from one is invalid and both proxies
  // drop it — the reference expands and the case still shows nothing. A body
  // shows the expansion, which is the whole question here.
  {
    // Declared as a divergence at the top of this file: upstream keys an inline
    // block to the file that declared it, this port merges them.
    name: 'a values block in one group, referenced by another',
    groups: [
      { name: 'A', value: `${B}v\nFROM-A\n${B}` },
      { name: 'B', value: `${A} resBody://{v}` },
    ],
  },
  {
    // The same shape the other way round: Default declares, a named group
    // refers. Upstream is symmetric about this and so is the divergence.
    name: 'a values block in Default, referenced by a named group',
    rules: `${B}v\nFROM-DEFAULT\n${B}`,
    groups: [{ name: 'A', value: `${A} resBody://{v}` }],
  },
  {
    // And the sharpest form: the group that declares the block **and** uses it
    // has its own value shadowed by another group's block of the same name.
    name: 'another group cannot shadow the block a group declared',
    groups: [
      { name: 'A', value: `${B}v\nFROM-A\n${B}\n${A} resBody://{v}` },
      { name: 'B', value: `${B}v\nFROM-B\n${B}` },
    ],
  },
  {
    // The same block and the same reference **inside one group**, which is the
    // shape that has to keep working. Without it the cases above could be read
    // as "inline values are broken" rather than "they are file-scoped".
    name: 'a values block referenced by its own group',
    groups: [{ name: 'A', value: `${B}v\nFROM-A\n${B}\n${A} resBody://{v}` }],
  },
  {
    name: 'an @ include inside a named group is resolved',
    groups: [{ name: 'A', value: `@${F('grp-inc.rules')}` }],
  },
  {
    // The include's rules take the position of the group that pulled them in,
    // so they outrank Default like any other line of that group.
    name: 'an include in a named group outranks Default',
    rules: `${A} method://PUT`,
    groups: [{ name: 'A', value: `@${F('grp-inc-method.rules')}` }],
  },
  {
    name: 'an unselected group does not apply its include',
    groups: [{ name: 'A', value: `@${F('grp-inc-off.rules')}`, selected: false }],
  },
  {
    // An `@` line and a plain line in one group, with the plain line first: the
    // include is spliced in where its line stands, not appended.
    name: 'an include is spliced in where its line stands',
    groups: [{ name: 'A', value: `${A} method://PUT\n@${F('grp-inc-method.rules')}` }],
  },
];
