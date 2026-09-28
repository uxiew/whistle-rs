#!/bin/sh
# Start a whistle-rs binary, fetch its console page, and check which page it is.
#
#   scripts/check-console.sh target/release/whistle-rs built
#   scripts/check-console.sh target/debug/whistle-rs placeholder
#
# built:       the page must be ui-src/dist/index.html byte for byte, after the
#              three stamps the server fills in (__VERSION__, __HOST__, __PORT__).
#              Proves the binary embeds *this* console build, not an older one
#              and not the placeholder.
# placeholder: the page must be the "console not built" placeholder. Proves a
#              checkout with no Node and no ui-src/dist still builds a binary
#              that runs and says why it has no console.
#
# Plain sh and curl on purpose: the placeholder check runs where Node is not
# installed. Exit 0 on a match, 1 on a mismatch, 2 on a usage or startup error.
set -eu

bin=${1:-}
want=${2:-}
if [ -z "$bin" ] || { [ "$want" != built ] && [ "$want" != placeholder ]; }; then
  echo "usage: $0 <whistle-rs binary> built|placeholder" >&2
  exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-18999}
work=$(mktemp -d "${TMPDIR:-/tmp}/check-console.XXXXXX")
pid=
# shellcheck disable=SC2329 # called by the trap below, which shellcheck cannot see
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

"$bin" --port "$port" --host 127.0.0.1 --no-persist --dir "$work/state" >"$work/log" 2>&1 &
pid=$!
tries=0
# --noproxy: with http_proxy set and no no_proxy, curl sends even a loopback
# request to that proxy, and this check hangs on a machine that uses one.
until curl -fsS --noproxy '*' --max-time 5 -o "$work/served.html" "http://127.0.0.1:$port/" 2>/dev/null; do
  tries=$((tries + 1))
  if [ "$tries" -gt 100 ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "whistle-rs did not answer on 127.0.0.1:$port; its log:" >&2
    cat "$work/log" >&2
    exit 2
  fi
  sleep 0.1
done

if [ "$want" = placeholder ]; then
  if grep -q 'console not built' "$work/served.html"; then
    echo "console: placeholder page served, as expected for a build without ui-src/dist"
    exit 0
  fi
  echo "console: expected the placeholder page, got something else" >&2
  exit 1
fi

dist="$root/ui-src/dist/index.html"
if [ ! -f "$dist" ]; then
  echo "console: no $dist to compare against; build the console first" >&2
  exit 2
fi
version=$("$bin" --version | awk '{print $2}')
sed -e "s/__VERSION__/$version/g" -e "s/__HOST__/127.0.0.1/g" -e "s/__PORT__/$port/g" "$dist" >"$work/expected.html"
if cmp -s "$work/expected.html" "$work/served.html"; then
  echo "console: served page is ui-src/dist/index.html ($(wc -c <"$dist" | tr -d ' ') bytes, stamps filled in)"
  exit 0
fi
if grep -q 'console not built' "$work/served.html"; then
  echo "console: the binary serves the placeholder — ui-src/dist was missing when it was compiled" >&2
else
  echo "console: the served page differs from ui-src/dist/index.html — the binary embeds another build" >&2
fi
exit 1
