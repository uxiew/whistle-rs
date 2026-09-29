// The request table's columns, in the order they are shown.
//
// `get` is the sort key, `text` what the cell reads; the Status column has no
// `text` because it draws a dot and a tag as well as a number, and the table
// renders it itself.

import type { SessionSummary } from './api';
import { clientOf, fmtBytes, fmtTime } from './format';

export interface Column {
  key: string;
  label: string;
  /** Fixed width, so a longer URL cannot re-flow the table mid-capture. */
  width?: string;
  /** Right-aligned, for the traffic columns. */
  num?: boolean;
  get: (s: SessionSummary) => string | number;
  text?: (s: SessionSummary) => string;
}

export const COLUMNS: Column[] = [
  { key: 'id', label: 'ID', width: '56px', get: (s) => s.id },
  { key: 'time_ms', label: 'Date', width: '78px', get: (s) => s.time_ms, text: (s) => fmtTime(s.time_ms) },
  { key: 'client_ip', label: 'Client', width: '124px', get: (s) => clientOf(s) },
  // Wide enough for a status and the longest failure tag, `client-tls`.
  { key: 'status', label: 'Status', width: '136px', get: (s) => s.status },
  { key: 'target', label: 'Policy', width: '170px', get: (s) => s.target },
  { key: 'up', label: 'Up', width: '62px', num: true, get: (s) => s.up || 0, text: (s) => fmtBytes(s.up) },
  { key: 'down', label: 'Down', width: '66px', num: true, get: (s) => s.down || 0, text: (s) => fmtBytes(s.down) },
  { key: 'method', label: 'Method', width: '64px', get: (s) => s.method },
  { key: 'url', label: 'URL', get: (s) => s.url },
];

/**
 * The dot colour for a row: the upgrade counts as a 3xx-ish informational, and
 * a request that did not complete is red whatever its status — a CONNECT the
 * client then refused was answered `200`, and a green dot would say it worked.
 */
export function statusClass(status: number, failed = false): string {
  if (failed) return 'st-5';
  return status === 101 ? 'st-3' : 'st-' + Math.floor(status / 100);
}
