/** Demand-driven recovery: true means retryable work remains; exceptions stop
 * this cycle. Disposal cancels scheduling, not an already durable delivery. */
export function createRecoveryPump(run: () => Promise<boolean>, onError: (error: unknown) => void, schedule = globalThis.setTimeout, cancel = globalThis.clearTimeout) {
  let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
  let stopped = false, running = false, requested = false, delay = 2000;
  const request = () => {
    if (stopped) return;
    requested = true;
    if (running || timer !== undefined) return;
    timer = schedule(async () => {
      timer = undefined;
      if (stopped) return;
      running = true;
      requested = false;
      let pending = false;
      try { pending = await run(); }
      catch (error) { requested = false; onError(error); }
      finally {
        running = false;
        delay = pending ? Math.min(delay * 2, 30000) : 2000;
        if (!stopped && (pending || requested)) request();
      }
    }, delay);
  };
  return {request, stop() { stopped = true; if (timer !== undefined) cancel(timer); timer = undefined; }};
}
