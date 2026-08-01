import type { SessionDetail, SessionSummary } from './api';

/**
 * The `curl` command that reproduces a request, for pasting into a terminal.
 *
 * Built from the headers as *forwarded*, not as received, so what it
 * reproduces is the request the origin actually saw — rules and all.
 */
export function asCurl(s: SessionSummary, d: SessionDetail | null): string {
  const q = (v: string) => "'" + String(v).replace(/'/g, "'\\''") + "'";
  const parts = ['curl', '-i', '-X', s.method, q(s.url)];
  for (const [k, v] of d?.req_headers ?? []) {
    // curl sets these itself, and a stale one breaks the replay.
    if (/^(content-length|host)$/i.test(k)) continue;
    parts.push('-H', q(k + ': ' + v));
  }
  if (d?.req_body?.text && !d.req_body.truncated) {
    parts.push('--data-raw', q(d.req_body.text));
  }
  return parts.join(' ');
}
