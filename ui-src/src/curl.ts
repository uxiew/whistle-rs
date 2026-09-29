import type { BodyCapture, SessionDetail, SessionSummary } from './api';

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
  const body = d?.req_body;
  const left = body && body.len > 0 ? bodyLeftOut(body) : null;
  if (left) {
    // A trailing shell comment, so the command still runs as one line and the
    // person pasting it reads why it will not send what the client sent.
    return `${parts.join(' ')} # body left out: ${left}`;
  }
  if (body?.text) parts.push('--data-raw', q(body.text));
  return parts.join(' ');
}

/**
 * Why the captured body cannot stand in for the one that was sent, if it
 * cannot. A binary body's `text` is the `[binary, N bytes]` marker, which as
 * `--data-raw` would send that sentence as the body; a cut or undecodable one
 * is a prefix of it.
 */
function bodyLeftOut(b: BodyCapture): string | null {
  if (b.undecodable) return 'its content-encoding would not decode';
  if (b.truncated) return `only part of its ${b.len} bytes was captured`;
  if (b.binary) return `it is binary (${b.len} bytes); save it from the Request Body tab and send it with --data-binary @file`;
  return null;
}
