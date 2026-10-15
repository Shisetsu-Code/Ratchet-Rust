/** Backpressure waits only when all delivery slots are occupied; no timer. */
export async function waitForSendCapacity(active: Set<Promise<void>>, limit: number): Promise<void> {
  while (active.size >= limit) await Promise.race(active);
}
