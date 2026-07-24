/** Sliding-window span. A limiter idle at least this long has let every timestamp age out. */
export const RATE_LIMITER_WINDOW_MS = 60_000;

/**
 * Sliding-window rate limiter. Keeps outgoing NetBird calls under a per-minute
 * cap so users never have to think about the API's 120 req/min limit.
 */
export class RateLimiter {
  private readonly windowMs = RATE_LIMITER_WINDOW_MS;
  private readonly timestamps: number[] = [];

  constructor(private readonly maxPerWindow: number) {}

  /** Resolves once a request slot is available within the window. */
  async acquire(now: () => number = Date.now): Promise<void> {
    // Loop because multiple awaiters may wake and re-check.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const t = now();
      while (this.timestamps.length && t - this.timestamps[0] >= this.windowMs) {
        this.timestamps.shift();
      }
      if (this.timestamps.length < this.maxPerWindow) {
        this.timestamps.push(t);
        return;
      }
      const waitMs = this.windowMs - (t - this.timestamps[0]) + 1;
      await sleep(waitMs);
    }
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}
