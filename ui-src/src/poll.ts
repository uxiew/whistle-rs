// Polling that backs off while the proxy is gone, and rests while nobody looks.
//
// The console used to ask every two seconds for as long as a tab was open,
// whether or not anything answered: a tab left on the Console pane after the
// proxy stopped collected 27,000 failed requests in fifteen hours (STATUS,
// 2026-10-01). Now a failure doubles the wait, up to half a minute, and the
// first answer brings it back to two seconds; a tab in the background asks
// nothing at all, and asks at once when it comes back, as it does when the
// window regains focus — someone who looks at the console wants it current.

import { state } from './store';

/** The wait while the proxy answers. */
const EVERY = 2000;
/** The longest wait while it does not. */
const SLOWEST = 30000;

/**
 * Call `tick` every two seconds, backing off while `state.offline` says the
 * proxy did not answer. Returns the function that stops it.
 *
 * `tick` does the asking and reports through `state.offline`, as every read
 * in `store.ts` does by way of `reach`; this only decides when to ask again.
 */
export function poll(tick: () => Promise<unknown> | unknown): () => void {
  let wait = EVERY;
  let timer: number | undefined;
  let busy = false;
  let stopped = false;

  const schedule = () => {
    if (stopped || busy || timer !== undefined || document.hidden) return;
    timer = window.setTimeout(run, wait);
  };

  const run = async () => {
    timer = undefined;
    // A hidden tab is woken by `visibilitychange`, not by the clock.
    if (stopped || busy || document.hidden) return;
    busy = true;
    try {
      await tick();
    } finally {
      busy = false;
    }
    wait = state.offline ? Math.min(wait * 2, SLOWEST) : EVERY;
    schedule();
  };

  // Someone is looking again: ask now, and start over from two seconds.
  const now = () => {
    if (stopped || document.hidden) return;
    window.clearTimeout(timer);
    timer = undefined;
    wait = EVERY;
    void run();
  };
  const onVisibility = () => {
    if (!document.hidden) now();
  };

  document.addEventListener('visibilitychange', onVisibility);
  window.addEventListener('focus', now);
  window.addEventListener('online', now);
  schedule();

  return () => {
    stopped = true;
    window.clearTimeout(timer);
    document.removeEventListener('visibilitychange', onVisibility);
    window.removeEventListener('focus', now);
    window.removeEventListener('online', now);
  };
}
