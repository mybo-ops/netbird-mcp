/**
 * Fixtures shared across test files. Each is a small, behaviour-neutral
 * stand-in for something every suite needs; keeping them here stops the same
 * shape being re-declared (and drifting) file by file.
 */

import { createHash } from "node:crypto";
import type { Logger } from "../src/logger.js";
import { DEFAULT_TOKEN_HEADER, DEFAULT_URL_HEADER } from "../src/config.js";

/** A logger that swallows everything — tests assert behaviour, not log lines. */
export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/** A real PKCE pair: code exchanges re-verify S256(verifier) === stored challenge. */
export function pkcePair(verifier = "test-code-verifier-abcdefghijklmnopqrstuvwxyz012345"): {
  verifier: string;
  challenge: string;
} {
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

/**
 * Header names are required by authFromRequest (the config module is their only
 * source of defaults); tests thread the defaults through explicitly, like the
 * HTTP entrypoint does.
 */
export const HEADER_NAMES = {
  tokenHeader: DEFAULT_TOKEN_HEADER,
  urlHeader: DEFAULT_URL_HEADER,
} as const;

/**
 * Allowlist threaded into OAuth cores/providers under test. Covers the base-URL
 * hosts the OAuth suites submit (`api.netbird.io`, the fictitious `self.hosted`),
 * so login flows proceed; tests that exercise a disallowed host pass their own.
 */
export const TEST_ALLOWED_API_HOSTS = ["api.netbird.io", "self.hosted"] as const;
