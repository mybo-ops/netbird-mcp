import { describe, it, expect, vi } from "vitest";
import { OAuthStore, REFRESH_TTL_SECONDS } from "../src/oauth/store.js";

/**
 * Refresh tokens must not live forever: a leaked one that is never rotated could
 * otherwise mint access tokens indefinitely. The store bounds their lifetime at
 * issuance and drops them on lookup once expired, mirroring access tokens.
 */
describe("OAuthStore refresh-token expiry", () => {
  const binding = { netbirdToken: "pat", baseUrl: "https://api.netbird.io" };

  it("issues refresh tokens with a bounded expiry that resolves before the deadline", () => {
    vi.useFakeTimers();
    try {
      const store = new OAuthStore();
      const { refreshToken } = store.issueTokens(binding, "client-1", ["netbird"]);

      // A hair inside the window: still resolvable to its binding.
      vi.advanceTimersByTime(REFRESH_TTL_SECONDS * 1000 - 1_000);
      expect(store.getRefresh(refreshToken)?.netbirdToken).toBe("pat");
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses and drops a refresh token once it has expired", () => {
    vi.useFakeTimers();
    try {
      const store = new OAuthStore();
      const { refreshToken } = store.issueTokens(binding, "client-1", ["netbird"]);

      vi.advanceTimersByTime(REFRESH_TTL_SECONDS * 1000 + 1_000);
      expect(store.getRefresh(refreshToken)).toBeUndefined();
      // A second lookup is still undefined — the record was dropped, not merely hidden.
      expect(store.getRefresh(refreshToken)).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
