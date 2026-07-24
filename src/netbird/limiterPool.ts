import { createHash } from "node:crypto";
import { RateLimiter, RATE_LIMITER_WINDOW_MS } from "./rateLimiter.js";

/**
 * Pool of {@link RateLimiter}s keyed by an opaque caller-supplied identifier, so
 * distinct callers get isolated budgets. Two uses today: per-tenant limiting for
 * tool calls (keyed by a NetBird token, so one account can't spend another's
 * slice of NetBird's per-account budget) and per-source limiting for OAuth login
 * verification (keyed by client IP, so one source can't monopolize it).
 *
 * The key is never retained verbatim — it's reduced to a truncated SHA-256 digest
 * before it touches the map, so a raw secret (or client IP) never lives in the pool.
 *
 * Entries are bounded two ways so an anonymous caller can't grow the pool
 * without limit (a memory-exhaustion DoS — rotate the token value every request
 * and each one mints a fresh key):
 *
 *   - **Idle TTL** reclaims limiters untouched for longer than {@link idleTtlMs}.
 *     This is safe for rate-limiting correctness because the constructor forces
 *     the TTL to be at least the limiter's own 60s window: a limiter idle that
 *     long has already let all its timestamps age out, so it carries no live
 *     budget to lose.
 *   - **Size cap** ({@link maxEntries}) is the hard backstop against a flood that
 *     mints keys faster than the TTL reclaims them — the least-recently-used
 *     entry is evicted once the cap is exceeded. Under a genuine flood of more
 *     than {@code maxEntries} *active* tenants within one window this can reset a
 *     victim's budget, but that only bites in the very scenario the cap exists to
 *     survive, and NetBird's own server-side limit still applies.
 *
 * The map is kept in ascending last-access order (an accessed entry is
 * re-inserted at the tail), so the least-recently-used entry is always at the
 * head — both eviction paths read from there.
 */

/** Hex digits of the SHA-256 digest kept as the map key — 64 bits, plenty to avoid collisions across callers. */
const KEY_HEX_CHARS = 16;
/** Default hard cap on retained limiters. Each limiter is tiny; this bounds worst-case memory. */
const DEFAULT_MAX_ENTRIES = 10_000;
/** Default idle reclaim window (10 min) — comfortably above the 60s rate-limit window, so eviction is lossless. */
const DEFAULT_IDLE_TTL_MS = 10 * 60_000;

/** A retained limiter plus the last time it was handed out; both fields are replaced, never mutated. */
interface PoolEntry {
  readonly limiter: RateLimiter;
  readonly lastAccess: number;
}

export interface LimiterPoolOptions {
  /** Hard cap on retained limiters; the least-recently-used is evicted beyond it. Must be >= 1. */
  readonly maxEntries?: number;
  /**
   * Idle time (ms) after which an untouched limiter is reclaimed. Must be at
   * least the rate-limit window ({@link RATE_LIMITER_WINDOW_MS}) so a reclaimed
   * limiter has already let its budget age out — otherwise a token that calls
   * sparsely-but-in-window would be evicted mid-window and reset, breaking its
   * count. The constructor enforces this rather than trusting the caller.
   */
  readonly idleTtlMs?: number;
  /**
   * Injectable clock (ms), for tests. Defaults to {@link Date.now}. Expected to be
   * non-decreasing; a rare backward step (e.g. NTP) only makes {@link reclaimIdle}
   * stop early and reclaim a little late — it never evicts a live entry, and the
   * size cap still bounds memory.
   */
  readonly now?: () => number;
}

export class LimiterPool {
  private readonly limiters = new Map<string, PoolEntry>();
  private readonly maxEntries: number;
  private readonly idleTtlMs: number;
  private readonly now: () => number;

  constructor(
    private readonly maxRequestsPerMinute: number,
    options: LimiterPoolOptions = {},
  ) {
    const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    const idleTtlMs = options.idleTtlMs ?? DEFAULT_IDLE_TTL_MS;
    // Fail fast on config that would silently break the pool: a sub-1 cap evicts
    // the entry it just inserted (every get mints a fresh, uncounted limiter), and
    // a TTL below the rate-limit window would reclaim still-budgeted limiters.
    if (!Number.isFinite(maxEntries) || maxEntries < 1) {
      throw new Error(`LimiterPool maxEntries must be a finite number >= 1, got ${maxEntries}`);
    }
    if (!Number.isFinite(idleTtlMs) || idleTtlMs < RATE_LIMITER_WINDOW_MS) {
      throw new Error(
        `LimiterPool idleTtlMs must be >= the rate-limit window (${RATE_LIMITER_WINDOW_MS}ms), got ${idleTtlMs}`,
      );
    }
    this.maxEntries = maxEntries;
    this.idleTtlMs = idleTtlMs;
    this.now = options.now ?? Date.now;
  }

  /** Number of limiters currently retained — for tests and operational visibility. */
  get size(): number {
    return this.limiters.size;
  }

  /** Returns the rate limiter for a caller key, creating it on first use. */
  get(callerKey: string): RateLimiter {
    const key = createHash("sha256").update(callerKey).digest("hex").slice(0, KEY_HEX_CHARS);
    const nowMs = this.now();
    this.reclaimIdle(nowMs);

    const existing = this.limiters.get(key);
    if (existing) {
      // Re-insert at the tail so recency order (and the LRU head) stays correct.
      this.limiters.delete(key);
      this.limiters.set(key, { limiter: existing.limiter, lastAccess: nowMs });
      return existing.limiter;
    }

    const limiter = new RateLimiter(this.maxRequestsPerMinute);
    this.limiters.set(key, { limiter, lastAccess: nowMs });
    this.evictOverflow();
    return limiter;
  }

  /**
   * Drop entries idle past the TTL. The map is in ascending last-access order,
   * so expired entries cluster at the head — stop at the first live one.
   */
  private reclaimIdle(nowMs: number): void {
    const cutoff = nowMs - this.idleTtlMs;
    for (const [key, entry] of this.limiters) {
      if (entry.lastAccess > cutoff) break;
      this.limiters.delete(key);
    }
  }

  /** Enforce the size cap by evicting least-recently-used entries (the map head). */
  private evictOverflow(): void {
    while (this.limiters.size > this.maxEntries) {
      const oldest = this.limiters.keys().next().value;
      if (oldest === undefined) break;
      this.limiters.delete(oldest);
    }
  }
}
