import { describe, it, expect, vi } from "vitest";
import { NetBirdOAuthProvider, type ProviderOptions } from "../src/oauth/provider.js";
import { DEFAULT_MAX_REQUESTS_PER_MINUTE, DEFAULT_REQUEST_TIMEOUT_MS } from "../src/config.js";
import { REFRESH_TTL_SECONDS } from "../src/oauth/store.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { silentLogger, pkcePair, TEST_ALLOWED_API_HOSTS } from "./helpers.js";

// A real PKCE pair: the exchange re-verifies S256(verifier) === stored challenge.
const { verifier: VERIFIER, challenge: CHALLENGE } = pkcePair(
  "oauth-test-code-verifier-abcdefghijklmnopqrstuvwxyz0123456789",
);

function newProvider(opts: Partial<ProviderOptions> = {}) {
  return new NetBirdOAuthProvider({
    logger: silentLogger,
    verifyPatOnLogin: false,
    maxRequestsPerMinute: DEFAULT_MAX_REQUESTS_PER_MINUTE,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    allowedApiHosts: TEST_ALLOWED_API_HOSTS,
    ...opts,
  });
}

async function registerClient(
  p: NetBirdOAuthProvider,
  clientId = "client-123",
): Promise<OAuthClientInformationFull> {
  const client: OAuthClientInformationFull = {
    client_id: clientId,
    redirect_uris: ["http://localhost:9999/cb"],
  } as OAuthClientInformationFull;
  await p.clientsStore.registerClient!(client);
  return client;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

/** Minimal stand-in for the Express req/res the login handler expects. */
function fakeLoginReqRes(body: Record<string, string>) {
  const req = { body } as unknown as import("express").Request;
  const state = { status: 200, redirected: undefined as string | undefined, sent: undefined as string | undefined };
  const res = {
    status(code: number) {
      state.status = code;
      return this;
    },
    setHeader() {
      return this;
    },
    send(body: string) {
      state.sent = body;
    },
    redirect(_code: number, url: string) {
      state.redirected = url;
    },
  } as unknown as import("express").Response;
  return { req, res, state };
}

/**
 * Mint a one-time authorization code through the provider's real login path
 * (core.completeLogin via handleLogin) instead of reaching into storage. The
 * store is private to the OAuth core, so this is the only legitimate seam.
 */
async function mintCode(
  p: NetBirdOAuthProvider,
  client: OAuthClientInformationFull,
  binding: { netbirdToken: string; baseUrl: string; codeChallenge?: string; scope?: string },
): Promise<string> {
  const { req, res, state } = fakeLoginReqRes({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    code_challenge: binding.codeChallenge ?? CHALLENGE,
    scope: binding.scope ?? "netbird",
    netbird_token: binding.netbirdToken,
    netbird_api_url: binding.baseUrl,
  });
  await p.handleLogin(req, res);
  return new URL(state.redirected!).searchParams.get("code")!;
}

describe("NetBirdOAuthProvider", () => {
  it("registers and retrieves clients", async () => {
    const p = newProvider();
    const client = await registerClient(p);
    expect(await p.clientsStore.getClient!("client-123")).toBe(client);
  });

  it("exchanges an authorization code for tokens bound to the NetBird PAT", async () => {
    const p = newProvider();
    const client = await registerClient(p);

    const code = await mintCode(p, client, {
      netbirdToken: "pat-abc",
      baseUrl: "https://api.netbird.io",
    });

    // SDK verifies PKCE separately; the challenge must be retrievable pre-exchange.
    expect(await p.challengeForAuthorizationCode(client, code)).toBe(CHALLENGE);

    const tokens = await p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]);
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();

    const info = await p.verifyAccessToken(tokens.access_token);
    expect(info.clientId).toBe("client-123");
    expect(info.extra).toEqual({ netbirdToken: "pat-abc", baseUrl: "https://api.netbird.io" });
  });

  it("rejects a reused (one-time) authorization code", async () => {
    const p = newProvider();
    const client = await registerClient(p);
    const code = await mintCode(p, client, {
      netbirdToken: "pat",
      baseUrl: "https://api.netbird.io",
      scope: "",
    });
    await p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]);
    await expect(
      p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]),
    ).rejects.toThrow(InvalidGrantError);
  });

  it("refresh_token grant rotates and preserves the NetBird binding", async () => {
    const p = newProvider();
    const client = await registerClient(p);
    const code = await mintCode(p, client, {
      netbirdToken: "pat-xyz",
      baseUrl: "https://self.hosted",
    });
    const first = await p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]);
    const refreshed = await p.exchangeRefreshToken(client, first.refresh_token!);

    expect(refreshed.access_token).not.toBe(first.access_token);
    const info = await p.verifyAccessToken(refreshed.access_token);
    expect(info.extra).toEqual({ netbirdToken: "pat-xyz", baseUrl: "https://self.hosted" });

    // Old refresh token is rotated out.
    await expect(p.exchangeRefreshToken(client, first.refresh_token!)).rejects.toThrow(
      InvalidGrantError,
    );
  });

  it("still exchanges a refresh token within its bounded lifetime", async () => {
    vi.useFakeTimers();
    try {
      const p = newProvider();
      const client = await registerClient(p);
      const code = await mintCode(p, client, { netbirdToken: "pat", baseUrl: "https://api.netbird.io" });
      const tokens = await p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]);

      // A minute short of the deadline it is still usable.
      await vi.advanceTimersByTimeAsync(REFRESH_TTL_SECONDS * 1000 - 60_000);
      const refreshed = await p.exchangeRefreshToken(client, tokens.refresh_token!);
      expect(refreshed.access_token).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses a refresh token once past its bounded lifetime", async () => {
    vi.useFakeTimers();
    try {
      const p = newProvider();
      const client = await registerClient(p);
      const code = await mintCode(p, client, { netbirdToken: "pat", baseUrl: "https://api.netbird.io" });
      const tokens = await p.exchangeAuthorizationCode(client, code, VERIFIER, client.redirect_uris[0]);

      // Past the bounded lifetime, the refresh grant is refused.
      await vi.advanceTimersByTimeAsync(REFRESH_TTL_SECONDS * 1000 + 60_000);
      await expect(p.exchangeRefreshToken(client, tokens.refresh_token!)).rejects.toThrow(
        InvalidGrantError,
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects unknown access tokens", async () => {
    const p = newProvider();
    await expect(p.verifyAccessToken("nope")).rejects.toThrow(InvalidTokenError);
  });

  it("revokes an access token only for the client that owns it (RFC 7009)", async () => {
    const p = newProvider();
    const owner = await registerClient(p, "owner");
    const intruder = await registerClient(p, "intruder");
    const code = await mintCode(p, owner, { netbirdToken: "pat", baseUrl: "https://api.netbird.io" });
    const tokens = await p.exchangeAuthorizationCode(owner, code, VERIFIER, owner.redirect_uris[0]);

    // A different client's revoke is a silent no-op — it still succeeds, but the
    // token is untouched (a client must not be able to kill another's tokens).
    await expect(p.revokeToken(intruder, { token: tokens.access_token })).resolves.toBeUndefined();
    expect((await p.verifyAccessToken(tokens.access_token)).clientId).toBe("owner");

    // The owning client's revoke removes it, as before.
    await p.revokeToken(owner, { token: tokens.access_token });
    await expect(p.verifyAccessToken(tokens.access_token)).rejects.toThrow(InvalidTokenError);
  });

  it("does not let a different client revoke another's refresh token", async () => {
    const p = newProvider();
    const owner = await registerClient(p, "owner");
    const intruder = await registerClient(p, "intruder");
    const code = await mintCode(p, owner, { netbirdToken: "pat", baseUrl: "https://api.netbird.io" });
    const tokens = await p.exchangeAuthorizationCode(owner, code, VERIFIER, owner.redirect_uris[0]);

    await p.revokeToken(intruder, { token: tokens.refresh_token! }); // no-op for a non-owner
    // The owner's refresh token still works.
    const refreshed = await p.exchangeRefreshToken(owner, tokens.refresh_token!);
    expect(refreshed.access_token).toBeTruthy();
  });

  it("tells the SDK to delegate PKCE so the code_verifier reaches the core", async () => {
    const p = newProvider();
    // The SDK's token handler passes code_verifier to exchangeAuthorizationCode
    // ONLY when this flag is set; the core's PKCE check is mandatory, so
    // without the flag every legitimate wire exchange would fail invalid_grant.
    expect(p.skipLocalPkceValidation).toBe(true);

    // The wire shape under the flag: verifier forwarded -> exchange succeeds;
    // verifier withheld (the pre-flag SDK behaviour) -> loud invalid_grant.
    const client = await registerClient(p);
    const code = await mintCode(p, client, { netbirdToken: "pat", baseUrl: "https://api.netbird.io" });
    await expect(
      p.exchangeAuthorizationCode(client, code, undefined, client.redirect_uris[0]),
    ).rejects.toThrow(InvalidGrantError);
  });

  it("honours the client-derived PAT verification outcome during login", async () => {
    // Invalid PAT (401 from the users endpoint, through the client) blocks login.
    const rejectingFetch = vi.fn(async (url, init) => {
      expect(String(url)).toBe("https://api.netbird.io/api/users");
      expect((init?.headers as Record<string, string>).Authorization).toBe("Token bad-pat");
      return jsonResponse({}, { status: 401 });
    }) as unknown as typeof fetch;

    const pInvalid = newProvider({ verifyPatOnLogin: true, fetchImpl: rejectingFetch });
    const invalidClient = await registerClient(pInvalid);
    const { req, res, state } = fakeLoginReqRes({
      client_id: invalidClient.client_id,
      redirect_uri: invalidClient.redirect_uris[0],
      state: "s1",
      code_challenge: "c1",
      scope: "netbird",
      netbird_token: "bad-pat",
      netbird_api_url: "https://api.netbird.io",
    });

    await pInvalid.handleLogin(req, res);

    expect(rejectingFetch).toHaveBeenCalledOnce();
    expect(state.redirected).toBeUndefined();
    expect(state.status).toBe(400);
    expect(state.sent).toMatch(/rejected/i);

    // Valid PAT (200 from the users endpoint) lets login proceed to the redirect.
    const acceptingFetch = vi.fn(async () => jsonResponse([{ id: "u1" }])) as unknown as typeof fetch;

    const pValid = newProvider({ verifyPatOnLogin: true, fetchImpl: acceptingFetch });
    const validClient = await registerClient(pValid);
    const { req: req2, res: res2, state: state2 } = fakeLoginReqRes({
      client_id: validClient.client_id,
      redirect_uri: validClient.redirect_uris[0],
      state: "s2",
      code_challenge: "c2",
      scope: "netbird",
      netbird_token: "good-pat",
      netbird_api_url: "https://api.netbird.io",
    });

    await pValid.handleLogin(req2, res2);

    expect(acceptingFetch).toHaveBeenCalledOnce();
    expect(state2.redirected).toContain("code=");
  });
});
