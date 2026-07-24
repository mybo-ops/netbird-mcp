import { describe, it, expect, vi } from "vitest";
import { resolveAuth, type AuthResolutionOptions } from "../src/auth/resolve.js";
import { NetBirdOAuthProvider } from "../src/oauth/provider.js";
import { DEFAULT_MAX_REQUESTS_PER_MINUTE, DEFAULT_REQUEST_TIMEOUT_MS } from "../src/config.js";
import { AuthError, type AuthContext } from "../src/auth/context.js";
import type { TokenVerification } from "../src/netbird/client.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { silentLogger, pkcePair, HEADER_NAMES } from "./helpers.js";

// A real PKCE pair: the code exchange re-verifies S256(verifier) === challenge.
const { verifier: VERIFIER, challenge: CHALLENGE } = pkcePair(
  "resolve-test-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789",
);

const ALLOWED = ["api.netbird.io", "self.hosted"];

/**
 * Direct-PAT options threaded from the entrypoint. Defaults to an enabled path
 * with a permissive allowlist and a verifier that says "ok", so each test
 * overrides only the axis it exercises. The verifier is a spy so tests can
 * assert it is NOT reached when an earlier gate rejects.
 */
function directOpts(over: Partial<AuthResolutionOptions> = {}): AuthResolutionOptions {
  return {
    ...HEADER_NAMES,
    allowedApiHosts: ALLOWED,
    directPatEnabled: true,
    verifyPat: vi.fn(async (): Promise<TokenVerification> => "ok"),
    ...over,
  };
}

function newProvider(): NetBirdOAuthProvider {
  return new NetBirdOAuthProvider({
    logger: silentLogger,
    verifyPatOnLogin: false,
    maxRequestsPerMinute: DEFAULT_MAX_REQUESTS_PER_MINUTE,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    allowedApiHosts: ALLOWED,
  });
}

/**
 * Drive the provider's real public flow to mint a genuine access token. The
 * store is private to the OAuth core now, so the code is minted through the
 * login form handler (the same entry point Claude's flow posts to) instead of
 * writing to storage directly.
 */
async function mintAccessToken(
  provider: NetBirdOAuthProvider,
  binding: { netbirdToken: string; baseUrl: string },
): Promise<string> {
  const client: OAuthClientInformationFull = {
    client_id: "client-123",
    redirect_uris: ["http://localhost:9999/cb"],
  } as OAuthClientInformationFull;
  await provider.clientsStore.registerClient!(client);

  const req = {
    body: {
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: CHALLENGE,
      scope: "netbird",
      netbird_token: binding.netbirdToken,
      netbird_api_url: binding.baseUrl,
    },
  } as unknown as import("express").Request;
  let redirected: string | undefined;
  const res = {
    status() {
      return this;
    },
    setHeader() {
      return this;
    },
    send() {},
    redirect(_code: number, url: string) {
      redirected = url;
    },
  } as unknown as import("express").Response;

  await provider.handleLogin(req, res);
  const code = new URL(redirected!).searchParams.get("code")!;

  const tokens = await provider.exchangeAuthorizationCode(
    client,
    code,
    VERIFIER,
    client.redirect_uris[0],
  );
  return tokens.access_token;
}

describe("resolveAuth — OAuth (Bearer) path", () => {
  it("resolves a valid Bearer token to the bound NetBird credential", async () => {
    const provider = newProvider();
    const accessToken = await mintAccessToken(provider, {
      netbirdToken: "pat-abc",
      baseUrl: "https://self.hosted",
    });

    const auth = await resolveAuth(
      { authorization: `Bearer ${accessToken}` },
      directOpts({ provider }),
    );
    expect(auth).toEqual({ token: "pat-abc", baseUrl: "https://self.hosted" });
  });

  it("rejects a Bearer token unknown to the OAuth store", async () => {
    const provider = newProvider();
    await expect(
      resolveAuth({ authorization: "Bearer nope" }, directOpts({ provider })),
    ).rejects.toMatchObject({ code: "unknown_token" });
  });

  it("does not run the direct-PAT verifier for the Bearer path", async () => {
    const provider = newProvider();
    const accessToken = await mintAccessToken(provider, {
      netbirdToken: "pat-abc",
      baseUrl: "https://self.hosted",
    });
    const opts = directOpts({ provider });
    await resolveAuth({ authorization: `Bearer ${accessToken}` }, opts);
    expect(opts.verifyPat).not.toHaveBeenCalled();
  });
});

describe("resolveAuth — direct-PAT path", () => {
  it("resolves a direct PAT via a custom header once verified", async () => {
    const auth = await resolveAuth(
      { "x-custom-token": "pat" },
      directOpts({ tokenHeader: "x-custom-token" }),
    );
    expect(auth).toEqual({ token: "pat", baseUrl: "https://api.netbird.io" });
  });

  it("resolves a direct PAT via Authorization: Token", async () => {
    const auth = await resolveAuth({ authorization: "Token pat" }, directOpts());
    expect(auth).toEqual({ token: "pat", baseUrl: "https://api.netbird.io" });
  });

  it("honors custom header names end to end for an allowlisted host", async () => {
    const auth = await resolveAuth(
      { "x-my-token": "pat", "x-my-url": "https://self.hosted/" },
      directOpts({ tokenHeader: "x-my-token", urlHeader: "x-my-url" }),
    );
    expect(auth).toEqual({ token: "pat", baseUrl: "https://self.hosted" });
  });

  it("rejects when no credentials are present", async () => {
    await expect(resolveAuth({}, directOpts())).rejects.toMatchObject({
      code: "missing_credentials",
    });
  });

  it("rejects a base URL that is not on the allowlist BEFORE any outbound call", async () => {
    const opts = directOpts();
    await expect(
      resolveAuth(
        { "x-netbird-token": "pat", "x-netbird-api-url": "https://evil.example.com" },
        opts,
      ),
    ).rejects.toMatchObject({ code: "forbidden_host" });
    expect(opts.verifyPat).not.toHaveBeenCalled();
  });

  it("rejects a metadata-IP base URL (SSRF floor) before any outbound call", async () => {
    const opts = directOpts();
    await expect(
      resolveAuth(
        { "x-netbird-token": "pat", "x-netbird-api-url": "http://169.254.169.254" },
        opts,
      ),
    ).rejects.toMatchObject({ code: "forbidden_host" });
    expect(opts.verifyPat).not.toHaveBeenCalled();
  });

  it("rejects a PAT that NetBird does not recognize (verification 'invalid')", async () => {
    await expect(
      resolveAuth(
        { authorization: "Token bad-pat" },
        directOpts({ verifyPat: vi.fn(async (): Promise<TokenVerification> => "invalid") }),
      ),
    ).rejects.toMatchObject({ code: "invalid_token" });
  });

  it("allows a PAT when verification is indeterminate ('unknown' fails open)", async () => {
    const auth = await resolveAuth(
      { authorization: "Token maybe" },
      directOpts({ verifyPat: vi.fn(async (): Promise<TokenVerification> => "unknown") }),
    );
    expect(auth).toEqual({ token: "maybe", baseUrl: "https://api.netbird.io" });
  });

  it("rejects the direct-PAT path entirely when it is disabled", async () => {
    const opts = directOpts({ directPatEnabled: false });
    await expect(
      resolveAuth({ "x-netbird-token": "pat" }, opts),
    ).rejects.toMatchObject({ code: "direct_pat_disabled" });
    expect(opts.verifyPat).not.toHaveBeenCalled();
  });
});

describe("resolveAuth — scheme and disabled-path edges", () => {
  async function authErrorCode(p: Promise<unknown>): Promise<string | undefined> {
    try {
      await p;
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      return (err as AuthError).code;
    }
    throw new Error("expected AuthError, but the promise resolved");
  }

  it("tags an unrecognized Authorization scheme as wrong_scheme", async () => {
    const code = await authErrorCode(
      resolveAuth({ authorization: "Basic dXNlcjpwdw==" }, directOpts()),
    );
    expect(code).toBe("wrong_scheme");
  });

  it("rejects Bearer via the direct-PAT path when OAuth is disabled (no provider)", async () => {
    // OAuth disabled -> direct-PAT is the enabled path, but it doesn't accept
    // Bearer; the caller gets the oauth-flavored reason so Claude can discover
    // the (absent) OAuth endpoints.
    const code = await authErrorCode(
      resolveAuth({ authorization: "Bearer some-access-token" }, directOpts()),
    );
    expect(code).toBe("oauth_disabled");
  });

  it("rejects an expired Bearer token as unknown_token", async () => {
    vi.useFakeTimers();
    try {
      const provider = newProvider();
      const token = await mintAccessToken(provider, {
        netbirdToken: "pat-x",
        baseUrl: "https://self.hosted",
      });
      vi.advanceTimersByTime(61 * 60 * 1000); // past the 1h access-token TTL
      const code = await authErrorCode(
        resolveAuth({ authorization: `Bearer ${token}` }, directOpts({ provider })),
      );
      expect(code).toBe("unknown_token");
    } finally {
      vi.useRealTimers();
    }
  });
});
