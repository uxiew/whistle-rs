// Formatting a traffic table can afford: short, aligned, never surprising.

import type { SessionSummary } from './api';

/** Bytes at the granularity a traffic column wants: never more than 4 chars. */
export function fmtBytes(n: number | undefined): string {
  if (!n) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return Math.round(n / 1024) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

export function fmtTime(ms: number | undefined): string {
  if (!ms) return '';
  const d = new Date(Number(ms));
  const p = (v: number) => String(v).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

export function fmtDateTime(ms: number | undefined): string {
  if (!ms) return '—';
  return new Date(Number(ms)).toLocaleString();
}

/** A short label for the client a request came from, for the source list. */
export function clientOf(s: SessionSummary): string {
  return s.client_ip || 'unknown';
}

export function hostOf(url: string | undefined): string {
  const m = /^[a-z]+:\/\/([^/?]+)/i.exec(url || '');
  return m ? m[1] : url || '';
}

/** Re-indent a body that is JSON, and leave anything else exactly as it is. */
export function prettyJson(text: string | undefined): string | null {
  const t = (text || '').trim();
  if (!t || !/^[[{]/.test(t)) return null;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return null;
  }
}

/** One header by name, case-insensitively. */
export function headerOf(pairs: [string, string][] | undefined, name: string): string {
  const hit = (pairs || []).find((p) => p[0].toLowerCase() === name);
  return hit ? hit[1] : '';
}
