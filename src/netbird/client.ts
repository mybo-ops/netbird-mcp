import type { AuthContext } from "../auth/context.js";
import type { Logger } from "../logger.js";
import { RateLimiter, sleep } from "./rateLimiter.js";

export interface NetBirdClientOptions {
  auth: AuthContext;
  logger: Logger;
  rateLimiter: RateLimiter;
  timeoutMs: number;
  /** Injectable for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Max retries on 429 / 5xx / network errors. */
  maxRetries?: number;
}

export class NetBirdApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "NetBirdApiError";
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  /** Query string params for GET requests. */
  query?: Record<string, string | number | boolean | undefined>;
  /** JSON body for write requests. */
  body?: unknown;
}

/** Cheap authenticated read used to check whether a token can authenticate. */
const USERS_PATH = "/api/users";

/** Outcome of a token-verification call: valid, rejected, or indeterminate. */
export type TokenVerification = "ok" | "invalid" | "unknown";

/**
 * Thin REST client for the NetBird public API. Handles auth, timeouts, a
 * client-side rate limit, and exponential backoff on 429/5xx (honoring
 * Retry-After). Transport-agnostic — one instance per AuthContext.
 */
export class NetBirdClient {
  private readonly fetchImpl: typeof fetch;
  private readonly maxRetries: number;

  constructor(private readonly opts: NetBirdClientOptions) {
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.maxRetries = opts.maxRetries ?? 4;
  }

  get<T = unknown>(path: string, query?: RequestOptions["query"]): Promise<T> {
    return this.request<T>(path, { method: "GET", query });
  }

  post<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, { method: "POST", body });
  }

  put<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, { method: "PUT", body });
  }

  delete<T = unknown>(path: string): Promise<T> {
    return this.request<T>(path, { method: "DELETE" });
  }

  /**
   * Verifies that this client's credentials can authenticate against its base
   * URL, via the same auth header, timeout, retry, and rate-limit path as every
   * other call. Maps the outcome to a three-state result: "ok" on success,
   * "invalid" on 401/403, and "unknown" for anything else (timeouts, network
   * failures, 5xx, or other unexpected errors).
   */
  async verifyToken(): Promise<TokenVerification> {
    try {
      await this.get(USERS_PATH);
      return "ok";
    } catch (err) {
      if (err instanceof NetBirdApiError && (err.status === 401 || err.status === 403)) {
        return "invalid";
      }
      return "unknown";
    }
  }

  private buildUrl(path: string, query?: RequestOptions["query"]): string {
    const url = new URL(this.opts.auth.baseUrl + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }

  private async request<T>(path: string, options: RequestOptions): Promise<T> {
    const method = options.method ?? "GET";
    const url = this.buildUrl(path, options.query);

    let attempt = 0;
    // Retry loop: 429 and 5xx are retried with backoff; other errors bubble up.
    while (true) {
      await this.opts.rateLimiter.acquire();

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.opts.timeoutMs);
      let res: Response;
      try {
        res = await this.fetchImpl(url, {
          method,
          headers: {
            Authorization: `Token ${this.opts.auth.token}`,
            Accept: "application/json",
            ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
          },
          body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timeout);
        if (attempt < this.maxRetries) {
          const delay = backoffMs(attempt);
          this.opts.logger.warn("netbird request failed, retrying", {
            method,
            path,
            attempt,
            delay,
          });
          await sleep(delay);
          attempt++;
          continue;
        }
        throw new NetBirdApiError(
          `Network error calling NetBird ${method} ${path}: ${(err as Error).message}`,
          0,
        );
      } finally {
        clearTimeout(timeout);
      }

      if (res.status === 429 || res.status >= 500) {
        if (attempt < this.maxRetries) {
          const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
          const delay = retryAfter ?? backoffMs(attempt);
          this.opts.logger.warn("netbird throttled/5xx, backing off", {
            method,
            path,
            status: res.status,
            attempt,
            delay,
          });
          await sleep(delay);
          attempt++;
          continue;
        }
      }

      const text = await res.text();
      const parsed = text ? safeJson(text) : undefined;

      if (!res.ok) {
        throw new NetBirdApiError(
          `NetBird ${method} ${path} failed with ${res.status}`,
          res.status,
          parsed ?? text,
        );
      }
      return parsed as T;
    }
  }
}

/**
 * Verify a NetBird PAT by constructing a short-lived client and issuing the
 * cheap authenticated read. The single wrapper both the OAuth login flow and the
 * direct-PAT request path use, so the auth-header convention, timeout, retry, and
 * rate limiting have exactly one implementation. Never throws — see verifyToken.
 */
export function verifyPat(
  auth: AuthContext,
  deps: { logger: Logger; rateLimiter: RateLimiter; timeoutMs: number; fetchImpl?: typeof fetch },
): Promise<TokenVerification> {
  return new NetBirdClient({ auth, ...deps }).verifyToken();
}

function backoffMs(attempt: number): number {
  // Exponential backoff with jitter: ~0.5s, 1s, 2s, 4s (+/- 20%).
  const base = 500 * 2 ** attempt;
  const jitter = base * 0.2 * (0.5 - deterministicJitter(attempt));
  return Math.round(base + jitter);
}

// Avoids Math.random (banned in some harness contexts); deterministic small jitter.
function deterministicJitter(attempt: number): number {
  return ((attempt * 2654435761) % 1000) / 1000;
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const secs = Number(value);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const date = Date.parse(value);
  if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  return undefined;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
