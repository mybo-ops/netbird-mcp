import { describe, it, expect, vi } from "vitest";
import { LimiterPool } from "../src/netbird/limiterPool.js";
import { RATE_LIMITER_WINDOW_MS } from "../src/netbird/rateLimiter.js";

describe("LimiterPool.get", () => {
  it("returns the same limiter instance for the same token", () => {
    const pool = new LimiterPool(120);
    expect(pool.get("tenant-token")).toBe(pool.get("tenant-token"));
  });

  it("returns isolated limiter instances for different tokens", () => {
    const pool = new LimiterPool(120);
    expect(pool.get("tenant-a")).not.toBe(pool.get("tenant-b"));
  });

  it("keeps per-tenant budgets isolated: one tenant's exhausted window does not block another", async () => {
    const pool = new LimiterPool(1);
    vi.useFakeTimers();
    try {
      const a = pool.get("tenant-a");
      const b = pool.get("tenant-b");

      await a.acquire(); // exhausts tenant-a's single slot

      // tenant-b has its own budget and must resolve immediately.
      let bResolved = false;
      const bAcquire = b.acquire().then(() => {
        bResolved = true;
      });
      await Promise.resolve();
      expect(bResolved).toBe(true);
      await bAcquire;
    } finally {
      vi.useRealTimers();
    }
  });

  it("makes over-budget acquires wait for the window to slide, then evicts and admits", async () => {
    const pool = new LimiterPool(2);
    vi.useFakeTimers();
    try {
      const limiter = pool.get("tenant-a");

      // Fill the 2/window budget at t=0.
      await limiter.acquire();
      await limiter.acquire();

      // The 3rd acquire must block until the window slides.
      let admitted = false;
      const third = limiter.acquire().then(() => {
        admitted = true;
      });

      // Flush microtasks; still blocked short of the window.
      await Promise.resolve();
      expect(admitted).toBe(false);

      await vi.advanceTimersByTimeAsync(59_000);
      expect(admitted).toBe(false);

      // Past the 60s window (+1ms slack): oldest timestamps evict, slot frees.
      await vi.advanceTimersByTimeAsync(1_001);
      await third;
      expect(admitted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("LimiterPool eviction (memory bound / DoS defense)", () => {
  /** A hand-cranked clock so TTL and recency are deterministic without fake timers. */
  function fixedClock(): { now: () => number; set: (t: number) => void; tick: () => void } {
    let t = 0;
    return { now: () => t, set: (v) => (t = v), tick: () => (t += 1) };
  }

  it("evicts the least-recently-used limiter once the size cap is exceeded", () => {
    const clock = fixedClock();
    const pool = new LimiterPool(120, { maxEntries: 2, idleTtlMs: 60_000, now: clock.now });

    const a = pool.get("a");
    clock.tick();
    pool.get("b");
    clock.tick();
    // Touch "a" so "b" is now the least-recently-used of the two.
    pool.get("a");
    clock.tick();
    // Inserting a third key overflows the cap and must evict the LRU ("b").
    pool.get("c");

    expect(pool.size).toBe(2);
    expect(pool.get("a")).toBe(a); // survivor keeps its instance
    expect(pool.get("b")).not.toBe(a); // "b" was reclaimed, re-get is a fresh limiter
  });

  it("evicts a limiter left idle past the TTL", () => {
    const clock = fixedClock();
    // Minimum legal TTL is the rate-limit window — a limiter idle that long has
    // already let every timestamp age out, so reclaiming it loses no budget.
    const pool = new LimiterPool(120, {
      maxEntries: 100,
      idleTtlMs: RATE_LIMITER_WINDOW_MS,
      now: clock.now,
    });

    const first = pool.get("t");
    clock.set(RATE_LIMITER_WINDOW_MS + 1); // idle beyond the TTL
    const second = pool.get("t");

    expect(second).not.toBe(first);
    expect(pool.size).toBe(1); // the stale entry was reclaimed, not accumulated
  });

  it("keeps an active token's limiter across requests within the TTL", () => {
    const clock = fixedClock();
    const pool = new LimiterPool(120, {
      maxEntries: 100,
      idleTtlMs: RATE_LIMITER_WINDOW_MS,
      now: clock.now,
    });

    const first = pool.get("t");
    clock.set(RATE_LIMITER_WINDOW_MS / 2); // each access refreshes recency, so it never ages out
    expect(pool.get("t")).toBe(first);
    clock.set(RATE_LIMITER_WINDOW_MS + RATE_LIMITER_WINDOW_MS / 3); // idle since last touch < TTL
    expect(pool.get("t")).toBe(first);
  });

  it("stays bounded under a flood of distinct tokens (rotating-token DoS)", () => {
    const clock = fixedClock();
    const pool = new LimiterPool(120, { maxEntries: 50, idleTtlMs: 60_000, now: clock.now });

    for (let i = 0; i < 10_000; i++) {
      pool.get(`rotating-${i}`);
      clock.tick();
    }

    expect(pool.size).toBeLessThanOrEqual(50);
  });

  it("bounds the pool on the real clock path (no injected clock)", () => {
    // Exercises the production default (now = Date.now): many iterations share a
    // millisecond, so this proves LRU eviction reads Map insertion order rather
    // than relying on distinct timestamps.
    const pool = new LimiterPool(120, { maxEntries: 25 });
    for (let i = 0; i < 5_000; i++) pool.get(`rotating-${i}`);
    expect(pool.size).toBe(25);
  });

  it("rejects config that would silently break the pool", () => {
    // A sub-1 cap would evict the entry get() just inserted; a TTL under the
    // window would reclaim still-budgeted limiters. Both must fail fast.
    expect(() => new LimiterPool(120, { maxEntries: 0 })).toThrow(/maxEntries/);
    expect(() => new LimiterPool(120, { idleTtlMs: RATE_LIMITER_WINDOW_MS - 1 })).toThrow(/idleTtlMs/);
  });
});
