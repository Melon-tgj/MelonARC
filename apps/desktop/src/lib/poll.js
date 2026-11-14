/**
 * A refresh loop that cannot pile up requests.
 *
 * Panels poll the core every few seconds. The loop runs one task at a time,
 * stops while the window is hidden (a background window does not need to ask),
 * and is cancelled by `stop`, which the panel calls when it is unmounted.
 */

/**
 * @param {() => Promise<void>} task
 * @param {{ every?: number }} [options]
 */
export function createPoll(task, { every = 4000 } = {}) {
  let timer = null;
  let running = false;
  let stopped = true;

  async function run() {
    if (running || stopped) return;
    running = true;
    try {
      await task();
    } catch {
      // A panel renders its own failure; the loop must keep its cadence.
    } finally {
      running = false;
    }
  }

  function schedule() {
    if (stopped) return;
    timer = setTimeout(async () => {
      await run();
      schedule();
    }, every);
  }

  function onVisibility() {
    if (document.visibilityState === "hidden") {
      if (timer) clearTimeout(timer);
      timer = null;
      return;
    }
    void run().then(schedule);
  }

  return {
    /** Run once immediately, then keep the cadence. */
    start() {
      if (!stopped) return;
      stopped = false;
      document.addEventListener("visibilitychange", onVisibility);
      void run().then(schedule);
    },

    /** Cancel the loop and its listener. */
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      document.removeEventListener("visibilitychange", onVisibility);
    },

    /** Ask for one refresh now, without disturbing the cadence. */
    refresh: run,
  };
}
