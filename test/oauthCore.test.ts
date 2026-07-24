import { describe, it, expect, vi } from "vitest";
import { OAuthCore, type OAuthCoreOptions } from "../src/oauth/core.js";
import { DEFAULT_MAX_REQUESTS_PER_MINUTE, DEFAULT_REQUEST_TIMEOUT_MS } from "../src/config.js";
import { renderLoginPage, type LoginPageParams } from "../src/oauth/loginPage.js";
import { InvalidGrantError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { silentLogger, pkcePair, TEST_ALLOWED_API_HOSTS } from "./helpers.js";

function newCore(opts: Partial<OAuthCoreOptions> = {}): OAuthCore {
  return new OAuthCore({
    logger: silentLogger,
    verifyPatOnLogin: false,
    maxRequestsPerMinute: DEFAULT_MAX_REQUESTS_PER_MINUTE,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    allowedApiHosts: TEST_ALLOWED_API_HOSTS,
    ...opts,
  });
}

function registerClient(
  core: OAuthCore,
  overrides: Partial<OAuthClientInformationFull> = {},
): OAuthClientInformationFull {
  const client: OAuthClientInformationFull = {
    client_id: "client-123",
    redirect_uris: ["http://localhost:9999/cb"],
    ...overrides,
  } as OAuthClientInformationFull;
  core.registerClient(client);
  return client;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

/** A complete, verifiable login form for a client — used by the PAT-verification suites. */
function patLoginForm(client: OAuthClientInformationFull, netbirdToken: string) {
  return {
    clientId: client.client_id,
    redirectUri: client.redirect_uris[0],
    codeChallenge: "c1",
    state: "s1",
    netbirdToken,
    netbirdApiUrl: "https://api.netbird.io",
  };
}

/** Strip the decision's `kind` (and `reason`, if present) down to renderable fields. */
function prefillOf(decision: { clientId: string } & Partial<LoginPageParams>): LoginPageParams {
  return {
    clientId: decision.clientId!,
    redirectUri: decision.redirectUri!,
    state: decision.state!,
    codeChallenge: decision.codeChallenge!,
    scope: decision.scope!,
    resource: decision.resource!,
  };
}

describe("OAuthCore.beginAuthorize", () => {
  it("yields a login challenge for a valid authorization request", () => {
    const core = newCore();
    const client = registerClient(core);

    const decision = core.beginAuthorize({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "c1",
      state: "s1",
      scopes: ["netbird"],
      resource: "https://example.com/mcp",
    });

    expect(decision).toEqual({
      kind: "challenge",
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      state: "s1",
      codeChallenge: "c1",
      scope: "netbird",
      resource: "https://example.com/mcp",
    });
  });

  it("rejects an unregistered redirect_uri before any rendering", () => {
    const core = newCore();
    const client = registerClient(core);

    const decision = core.beginAuthorize({
      clientId: client.client_id,
      redirectUri: "https://attacker.example/cb",
      codeChallenge: "c1",
    });

    expect(decision.kind).toBe("error");
    expect((decision as { reason: string }).reason).toMatch(/not registered/i);
  });

  it("rejects an unknown client", () => {
    const core = newCore();
    const decision = core.beginAuthorize({
      clientId: "does-not-exist",
      redirectUri: "http://localhost:9999/cb",
      codeChallenge: "c1",
    });

    expect(decision.kind).toBe("error");
    expect((decision as { reason: string }).reason).toMatch(/unknown/i);
  });

  it("rejects a missing PKCE code challenge", () => {
    const core = newCore();
    const client = registerClient(core);
    const decision = core.beginAuthorize({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "",
    });
    expect(decision.kind).toBe("error");
  });
});

describe("OAuthCore.completeLogin", () => {
  it("issues a redirect whose code exchanges for tokens with the right binding", async () => {
    const core = newCore();
    const client = registerClient(core);
    const { verifier, challenge } = pkcePair();

    const decision = await core.completeLogin({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: challenge,
      state: "s1",
      scope: "netbird",
      netbirdToken: "pat-abc",
      netbirdApiUrl: "https://self.hosted",
    });

    expect(decision.kind).toBe("redirect");
    const location = (decision as { location: string }).location;
    expect(location.startsWith(client.redirect_uris[0])).toBe(true);
    const url = new URL(location);
    expect(url.searchParams.get("state")).toBe("s1");
    const code = url.searchParams.get("code")!;
    expect(code).toBeTruthy();

    expect(core.challengeForCode(code)).toBe(challenge);
    const tokens = core.exchangeAuthorizationCode(
      client.client_id,
      code,
      verifier,
      client.redirect_uris[0],
    );
    expect(tokens.access_token).toBeTruthy();

    const auth = core.resolveBinding(tokens.access_token);
    expect(auth).toEqual({ token: "pat-abc", baseUrl: "https://self.hosted" });
  });

  const errorCases: Array<{
    name: string;
    build: (client: OAuthClientInformationFull) => Parameters<OAuthCore["completeLogin"]>[0];
    reasonPattern: RegExp;
  }> = [
    {
      name: "missing PAT field",
      build: (client) => ({
        clientId: client.client_id,
        redirectUri: client.redirect_uris[0],
        codeChallenge: "c",
        netbirdToken: "",
      }),
      reasonPattern: /paste your NetBird Personal Access Token/i,
    },
    {
      name: "invalid OAuth params (missing code challenge)",
      build: (client) => ({
        clientId: client.client_id,
        redirectUri: client.redirect_uris[0],
        codeChallenge: "",
        netbirdToken: "pat",
      }),
      reasonPattern: /invalid or has expired/i,
    },
    {
      name: "missing OAuth params (unknown client)",
      build: () => ({
        clientId: "unknown-client",
        redirectUri: "http://localhost:9999/cb",
        codeChallenge: "c",
        netbirdToken: "pat",
      }),
      reasonPattern: /invalid or has expired/i,
    },
    {
      name: "unregistered redirect_uri",
      build: (client) => ({
        clientId: client.client_id,
        redirectUri: "https://attacker.example/cb",
        codeChallenge: "c",
        netbirdToken: "pat",
      }),
      reasonPattern: /not registered/i,
    },
  ];

  it.each(errorCases)("re-renders safely on $name", async ({ build, reasonPattern }) => {
    const core = newCore();
    const client = registerClient(core);
    const decision = await core.completeLogin(build(client));

    expect(decision.kind).toBe("error");
    const errorDecision = decision as { reason: string } & LoginPageParams;
    expect(errorDecision.reason).toMatch(reasonPattern);

    // Re-rendering must not throw — the safe-render contract.
    expect(() => renderLoginPage(prefillOf(errorDecision), errorDecision.reason)).not.toThrow();
  });

  it("re-renders safely when the PAT is rejected by NetBird", async () => {
    const rejectingFetch = vi.fn(async () => jsonResponse({}, { status: 401 })) as unknown as typeof fetch;
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: rejectingFetch });
    const client = registerClient(core);

    const decision = await core.completeLogin({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "c",
      netbirdToken: "bad-pat",
      netbirdApiUrl: "https://api.netbird.io",
    });

    expect(rejectingFetch).toHaveBeenCalledOnce();
    expect(decision.kind).toBe("error");
    const errorDecision = decision as { reason: string } & LoginPageParams;
    expect(errorDecision.reason).toMatch(/rejected/i);
    expect(() => renderLoginPage(prefillOf(errorDecision), errorDecision.reason)).not.toThrow();
  });
});

describe("OAuthCore.exchangeAuthorizationCode — PKCE re-verification (defence in depth)", () => {
  async function mintCode(core: OAuthCore, client: OAuthClientInformationFull, challenge: string) {
    const decision = await core.completeLogin({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: challenge,
      netbirdToken: "pat-abc",
      netbirdApiUrl: "https://self.hosted",
    });
    const location = (decision as { location: string }).location;
    return new URL(location).searchParams.get("code")!;
  }

  it("rejects a wrong code verifier with invalid_grant", async () => {
    const core = newCore();
    const client = registerClient(core);
    const { challenge } = pkcePair();
    const code = await mintCode(core, client, challenge);

    expect(() =>
      core.exchangeAuthorizationCode(
        client.client_id,
        code,
        "the-wrong-verifier",
        client.redirect_uris[0],
      ),
    ).toThrow(InvalidGrantError);
  });

  it("rejects a missing code verifier with invalid_grant", async () => {
    const core = newCore();
    const client = registerClient(core);
    const { challenge } = pkcePair();
    const code = await mintCode(core, client, challenge);

    expect(() =>
      core.exchangeAuthorizationCode(client.client_id, code, undefined, client.redirect_uris[0]),
    ).toThrow(InvalidGrantError);
  });

  it("fails a wrong verifier even when challengeForCode was never called first", async () => {
    const core = newCore();
    const client = registerClient(core);
    const { challenge } = pkcePair();
    const code = await mintCode(core, client, challenge);

    // No prior challengeForCode/challengeForAuthorizationCode call: the re-check
    // must not depend on the SDK having looked the challenge up first.
    expect(() =>
      core.exchangeAuthorizationCode(
        client.client_id,
        code,
        "the-wrong-verifier",
        client.redirect_uris[0],
      ),
    ).toThrow(InvalidGrantError);
  });

  it("accepts the correct verifier end-to-end through the real login flow", async () => {
    const core = newCore();
    const client = registerClient(core);
    const { verifier, challenge } = pkcePair();
    const code = await mintCode(core, client, challenge);

    const tokens = core.exchangeAuthorizationCode(
      client.client_id,
      code,
      verifier,
      client.redirect_uris[0],
    );
    expect(tokens.access_token).toBeTruthy();
    expect(core.resolveBinding(tokens.access_token)).toEqual({
      token: "pat-abc",
      baseUrl: "https://self.hosted",
    });
  });
});

describe("login page XSS escaping (via the core's decision output)", () => {
  it("escapes a hostile state value reflected in a login challenge", () => {
    const core = newCore();
    const client = registerClient(core);
    const hostileState = `"><script>alert(1)</script>`;

    const decision = core.beginAuthorize({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "c1",
      state: hostileState,
    }) as { kind: "challenge" } & LoginPageParams;

    expect(decision.kind).toBe("challenge");
    const html = renderLoginPage(prefillOf(decision));

    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain(`value="${hostileState}"`);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&quot;&gt;&lt;script&gt;");
  });

  it("escapes hostile values reflected in a login error re-render", async () => {
    const core = newCore();
    const client = registerClient(core);
    const hostileScope = `netbird" onmouseover="alert(1)`;

    const decision = (await core.completeLogin({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "c1",
      scope: hostileScope,
      netbirdToken: "", // trigger the missing-PAT error path
    })) as { kind: "error"; reason: string } & LoginPageParams;

    expect(decision.kind).toBe("error");
    const html = renderLoginPage(prefillOf(decision), decision.reason);

    expect(html).not.toContain(`value="${hostileScope}"`);
    expect(html).toContain("&quot; onmouseover=&quot;alert(1)");
  });
});

describe("OAuthCore.completeLogin — API URL validation and indeterminate verification", () => {
  function loginForm(client: OAuthClientInformationFull) {
    return {
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      codeChallenge: "c1",
      state: "s1",
      netbirdToken: "pat-1",
    };
  }

  it("rejects a non-http(s) NetBird API URL before any verification fetch", async () => {
    const fetchSpy = vi.fn();
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: fetchSpy as unknown as typeof fetch });
    const client = registerClient(core);

    const decision = await core.completeLogin({
      ...loginForm(client),
      netbirdApiUrl: "javascript:alert(1)",
    });

    expect(decision.kind).toBe("error");
    expect((decision as { reason: string }).reason).toMatch(/valid http/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a NetBird API URL whose host is not on the allowlist, before any fetch", async () => {
    const fetchSpy = vi.fn();
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: fetchSpy as unknown as typeof fetch });
    const client = registerClient(core);

    const decision = await core.completeLogin({
      ...loginForm(client),
      netbirdApiUrl: "https://evil.example.com",
    });

    expect(decision.kind).toBe("error");
    expect((decision as { reason: string }).reason).toMatch(/allowlist|not allowed/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a metadata-IP NetBird API URL before any fetch (SSRF oracle closed)", async () => {
    const fetchSpy = vi.fn();
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: fetchSpy as unknown as typeof fetch });
    const client = registerClient(core);

    const decision = await core.completeLogin({
      ...loginForm(client),
      netbirdApiUrl: "http://169.254.169.254",
    });

    expect(decision.kind).toBe("error");
    expect((decision as { reason: string }).reason).toMatch(/private|loopback|link-local|metadata|allowlist/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("lets an allowlisted self-hosted URL proceed to a redirect", async () => {
    const acceptingFetch = vi.fn(async () => jsonResponse([{ id: "u1" }])) as unknown as typeof fetch;
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: acceptingFetch });
    const client = registerClient(core);

    const decision = await core.completeLogin({
      ...loginForm(client),
      netbirdApiUrl: "https://self.hosted",
    });

    expect(decision.kind).toBe("redirect");
    expect(acceptingFetch).toHaveBeenCalledOnce();
  });

  it("lets login proceed when PAT verification is indeterminate (network failure)", async () => {
    const failingFetch = (() =>
      Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch;
    const core = newCore({ verifyPatOnLogin: true, fetchImpl: failingFetch });
    const client = registerClient(core);

    // The verification call retries with real backoff sleeps before settling
    // on "unknown" — pump fake timers through them instead of waiting.
    vi.useFakeTimers();
    try {
      const pending = core.completeLogin(loginForm(client));
      await vi.runAllTimersAsync();
      const decision = await pending;
      expect(decision.kind).toBe("redirect");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("OAuthCore — configured rate limit governs login-path PAT verification", () => {
  it("shares a maxRequestsPerMinute=1 limiter across logins, delaying the second verification", async () => {
    const acceptingFetch = vi.fn(async () => jsonResponse([{ id: "u1" }])) as unknown as typeof fetch;
    const core = newCore({
      verifyPatOnLogin: true,
      maxRequestsPerMinute: 1,
      fetchImpl: acceptingFetch,
    });
    const client = registerClient(core);

    vi.useFakeTimers();
    try {
      // First login consumes the single slot in the shared verify limiter.
      const first = await core.completeLogin(patLoginForm(client, "pat-1"));
      expect(first.kind).toBe("redirect");
      expect(acceptingFetch).toHaveBeenCalledTimes(1);

      // Second login must wait for the sliding window before its PAT check fires.
      const pending = core.completeLogin(patLoginForm(client, "pat-2"));
      await Promise.resolve();
      await Promise.resolve();
      expect(acceptingFetch).toHaveBeenCalledTimes(1);

      // Advancing past the one-minute window releases the throttled verification.
      await vi.advanceTimersByTimeAsync(61_000);
      const second = await pending;
      expect(second.kind).toBe("redirect");
      expect(acceptingFetch).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("OAuthCore — per-source login rate limiting isolates a noisy source", () => {
  it("throttles one source on its own sub-limiter while another source still logs in", async () => {
    const acceptingFetch = vi.fn(async () => jsonResponse([{ id: "u1" }])) as unknown as typeof fetch;
    // Global budget 20/min -> each source gets floor(20/10)=2 before its own
    // sub-limiter throttles, so no single source can drain the shared budget.
    const core = newCore({ verifyPatOnLogin: true, maxRequestsPerMinute: 20, fetchImpl: acceptingFetch });
    const client = registerClient(core);
    const noisy = "1.1.1.1";
    const other = "2.2.2.2";

    vi.useFakeTimers();
    try {
      // The noisy source spends its per-source budget (2 verifications).
      await core.completeLogin(patLoginForm(client, "pat-a1"), noisy);
      await core.completeLogin(patLoginForm(client, "pat-a2"), noisy);
      expect(acceptingFetch).toHaveBeenCalledTimes(2);

      // Its 3rd attempt stalls on its OWN sub-limiter (not the shared budget).
      const stalled = core.completeLogin(patLoginForm(client, "pat-a3"), noisy);
      await Promise.resolve();
      await Promise.resolve();
      expect(acceptingFetch).toHaveBeenCalledTimes(2);

      // A different source logs in immediately — the shared budget wasn't exhausted.
      const otherLogin = await core.completeLogin(patLoginForm(client, "pat-b"), other);
      expect(otherLogin.kind).toBe("redirect");
      expect(acceptingFetch).toHaveBeenCalledTimes(3);

      // Once the noisy source's window slides, its stalled attempt drains.
      await vi.advanceTimersByTimeAsync(61_000);
      expect((await stalled).kind).toBe("redirect");
      expect(acceptingFetch).toHaveBeenCalledTimes(4);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("login page escaping — remaining reflected params", () => {
  it("escapes hostile client_id, redirect_uri, resource and code_challenge reflections", () => {
    const hostile = '"><script>alert(1)</script>';
    const html = renderLoginPage({
      clientId: hostile,
      redirectUri: `http://localhost:9999/cb?x=${hostile}`,
      state: hostile,
      codeChallenge: hostile,
      scope: hostile,
      resource: hostile,
    });
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });
});
