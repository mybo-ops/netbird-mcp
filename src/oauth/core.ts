import { createHash, timingSafeEqual } from "node:crypto";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { normalizeBaseUrl } from "../config.js";
import type { Logger } from "../logger.js";
import { AuthContext, AuthError } from "../auth/context.js";
import { verifyPat, type TokenVerification } from "../netbird/client.js";
import { checkApiUrl } from "../netbird/apiUrlPolicy.js";
import { RateLimiter } from "../netbird/rateLimiter.js";
import { LimiterPool } from "../netbird/limiterPool.js";
import { ACCESS_TTL_SECONDS, OAuthStore, type NetBirdBinding } from "./store.js";
import type { LoginPageParams } from "./loginPage.js";

/**
 * A single login source may spend at most 1/N of the global verify budget before
 * its own sub-limiter throttles it — so one noisy source can't drain the shared
 * budget and stall everyone else's logins.
 */
const LOGIN_VERIFY_SOURCE_SHARE = 10;
/** Source key used when the caller can't attribute a request (e.g. IP unavailable). */
const UNKNOWN_LOGIN_SOURCE = "unknown";

export interface OAuthCoreOptions {
  logger: Logger;
  /** Verify a NetBird PAT during login by making a cheap read call. */
  verifyPatOnLogin?: boolean;
  /**
   * Hosts a submitted netbird_api_url may target — the resolved
   * config.allowedApiHosts. The login flow checks against this before any
   * verification fetch, so the form can't be used to reach an internal host.
   */
  allowedApiHosts: readonly string[];
  /**
   * Client-side per-minute cap for login-path PAT verification. Required — the
   * operator's resolved config (NETBIRD_MAX_RPM) is threaded down here so the
   * same limit governs login verification and tool calls; no default lives here.
   */
  maxRequestsPerMinute: number;
  /**
   * Per-request timeout (ms) for login-path PAT verification. Required — the
   * operator's resolved config (NETBIRD_TIMEOUT_MS) is threaded down here; no
   * default lives here.
   */
  requestTimeoutMs: number;
  fetchImpl?: typeof fetch;
}

/** Raw inputs to the authorization decision — one per OAuthServerProvider#authorize call. */
export interface BeginAuthorizeParams {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scopes?: string[];
  resource?: string;
}

/** Raw form fields posted from the login page. All optional: the form is untrusted input. */
export interface LoginSubmission {
  clientId?: string;
  redirectUri?: string;
  state?: string;
  codeChallenge?: string;
  scope?: string;
  resource?: string;
  netbirdToken?: string;
  netbirdApiUrl?: string;
}

/** The OAuth params the login page must echo back, whichever decision follows. */
export type LoginPrefill = LoginPageParams;

export type OAuthChallenge = { kind: "challenge" } & LoginPrefill;
export type OAuthLoginError = { kind: "error"; reason: string } & LoginPrefill;
export type OAuthRedirect = { kind: "redirect"; location: string };

export type BeginAuthorizeResult = OAuthChallenge | OAuthLoginError;
export type CompleteLoginResult = OAuthRedirect | OAuthLoginError;

/**
 * Framework-free OAuth 2.1 core for the NetBird connector. Owns the authorization
 * decision, the login-completion decision, and the token protocol (code exchange,
 * refresh rotation, verification, revocation). Nothing here knows about HTTP —
 * inputs are plain values and outputs are explicit discriminated results; the web
 * adapter (NetBirdOAuthProvider) is the only thing that talks req/res.
 *
 * Claude registers dynamically (RFC 7591) and drives an authorization-code + PKCE
 * flow. `beginAuthorize` decides whether to show the login challenge (where a user
 * pastes a NetBird PAT); `completeLogin` verifies it and binds the issued code to
 * it. Tool code never sees OAuth — it only ever receives a resolved AuthContext via
 * resolveBinding.
 */
export class OAuthCore {
  private readonly store = new OAuthStore();
  private readonly logger: Logger;
  private readonly verifyPat: boolean;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly allowedApiHosts: readonly string[];
  // Shared across all logins so a burst of login attempts is throttled as one
  // stream, not one fresh (and therefore never-tripping) limiter per attempt.
  private readonly verifyLimiter: RateLimiter;
  // Per-source sub-limiters (keyed by client IP), each a small slice of the
  // global budget, so a single source can't monopolize verification. Bounded in
  // memory by LimiterPool's own eviction, so distinct sources can't grow it.
  private readonly verifySourceLimiters: LimiterPool;

  constructor(opts: OAuthCoreOptions) {
    this.logger = opts.logger;
    this.verifyPat = opts.verifyPatOnLogin ?? true;
    this.timeoutMs = opts.requestTimeoutMs;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.allowedApiHosts = opts.allowedApiHosts;
    this.verifyLimiter = new RateLimiter(opts.maxRequestsPerMinute);
    const perSourceMax = Math.max(1, Math.floor(opts.maxRequestsPerMinute / LOGIN_VERIFY_SOURCE_SHARE));
    this.verifySourceLimiters = new LimiterPool(perSourceMax);
  }

  // --- dynamic client registration (backs the adapter's clientsStore) ---

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.store.getClient(clientId);
  }

  registerClient(client: OAuthClientInformationFull): void {
    this.store.saveClient(client);
  }

  // --- authorization decision ---

  /**
   * Decides what /authorize should do: render the login challenge, or reject
   * before anything is rendered. Client lookup, redirect-URI registration, and
   * PKCE presence are all validated here — the SDK's own authorize handler
   * already checks client/redirect_uri before calling in, so in practice this
   * only ever yields "challenge"; the error branch is defense in depth and the
   * seam a test can drive directly.
   */
  beginAuthorize(params: BeginAuthorizeParams): BeginAuthorizeResult {
    const prefill: LoginPrefill = {
      clientId: params.clientId,
      redirectUri: params.redirectUri,
      state: params.state ?? "",
      codeChallenge: params.codeChallenge,
      scope: (params.scopes ?? []).join(" "),
      resource: params.resource ?? "",
    };

    const client = this.store.getClient(params.clientId);
    if (!client) {
      return { kind: "error", reason: "Unknown OAuth client.", ...prefill };
    }
    if (!params.redirectUri || !client.redirect_uris.includes(params.redirectUri)) {
      return {
        kind: "error",
        reason: "The redirect target is not registered for this client.",
        ...prefill,
      };
    }
    if (!params.codeChallenge) {
      return { kind: "error", reason: "Missing PKCE code challenge.", ...prefill };
    }
    return { kind: "challenge", ...prefill };
  }

  // --- login completion ---

  /**
   * Validates the login form, optionally verifies the PAT against NetBird, and
   * on success binds a one-time authorization code to the credential. Returns a
   * redirect (with the code) or an error to re-render, never throws.
   */
  async completeLogin(
    form: LoginSubmission,
    sourceKey: string = UNKNOWN_LOGIN_SOURCE,
  ): Promise<CompleteLoginResult> {
    const prefill: LoginPrefill = {
      clientId: form.clientId ?? "",
      redirectUri: form.redirectUri ?? "",
      state: form.state ?? "",
      codeChallenge: form.codeChallenge ?? "",
      scope: form.scope ?? "",
      resource: form.resource ?? "",
    };
    const netbirdToken = (form.netbirdToken ?? "").trim();
    const baseUrl = normalizeBaseUrl(form.netbirdApiUrl);
    const urlCheck = checkApiUrl(baseUrl, this.allowedApiHosts);
    if (!urlCheck.allowed) {
      return {
        kind: "error",
        reason: `That NetBird API URL is not allowed: ${urlCheck.reason}.`,
        ...prefill,
      };
    }

    const client = this.store.getClient(prefill.clientId);
    if (!client || !prefill.codeChallenge || !prefill.redirectUri) {
      return {
        kind: "error",
        reason: "This authorization request is invalid or has expired. Start again from Claude.",
        ...prefill,
      };
    }
    if (!client.redirect_uris.includes(prefill.redirectUri)) {
      return {
        kind: "error",
        reason: "The redirect target is not registered for this client.",
        ...prefill,
      };
    }
    if (!netbirdToken) {
      return { kind: "error", reason: "Please paste your NetBird Personal Access Token.", ...prefill };
    }

    if (this.verifyPat) {
      const validity = await this.checkPat(netbirdToken, baseUrl, sourceKey);
      if (validity === "invalid") {
        return {
          kind: "error",
          reason: "That NetBird token was rejected (401/403). Check the token and API URL.",
          ...prefill,
        };
      }
    }

    const code = this.store.createCode({
      clientId: prefill.clientId,
      redirectUri: prefill.redirectUri,
      codeChallenge: prefill.codeChallenge,
      scopes: prefill.scope ? prefill.scope.split(" ").filter(Boolean) : [],
      netbirdToken,
      baseUrl,
    });

    const url = new URL(prefill.redirectUri);
    url.searchParams.set("code", code);
    if (prefill.state) url.searchParams.set("state", prefill.state);
    this.logger.info("oauth authorization granted", { client_id: prefill.clientId });
    return { kind: "redirect", location: url.toString() };
  }

  // --- token protocol (semantics unchanged; only the location moved) ---

  challengeForCode(code: string): string {
    const challenge = this.store.challengeForCode(code);
    if (!challenge) throw new InvalidGrantError("unknown or expired authorization code");
    return challenge;
  }

  exchangeAuthorizationCode(
    clientId: string,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
  ): OAuthTokens {
    const rec = this.store.takeCode(authorizationCode);
    if (!rec) throw new InvalidGrantError("unknown or expired authorization code");
    if (rec.clientId !== clientId) throw new InvalidGrantError("client mismatch");
    if (redirectUri && redirectUri !== rec.redirectUri) {
      throw new InvalidGrantError("redirect_uri mismatch");
    }
    // Re-verify PKCE ourselves after consuming the code. The SDK's token handler
    // already checked this via challengeForCode, but recomputing the S256
    // challenge from the supplied verifier here — with no dependence on any prior
    // lookup — means a future SDK reordering its internal calls can never let a
    // code be exchanged without a matching verifier.
    if (!pkceMatches(codeVerifier, rec.codeChallenge)) {
      throw new InvalidGrantError("PKCE verification failed");
    }

    const { accessToken, refreshToken } = this.store.issueTokens(
      { netbirdToken: rec.netbirdToken, baseUrl: rec.baseUrl },
      clientId,
      rec.scopes,
    );
    return this.tokenResponse(accessToken, refreshToken, rec.scopes);
  }

  exchangeRefreshToken(clientId: string, refreshToken: string, scopes?: string[]): OAuthTokens {
    const rec = this.store.getRefresh(refreshToken);
    if (!rec || rec.clientId !== clientId) {
      throw new InvalidGrantError("unknown refresh token");
    }
    const grantedScopes = scopes && scopes.length ? scopes : rec.scopes;
    const { accessToken, refreshToken: newRefresh } = this.store.issueTokens(
      { netbirdToken: rec.netbirdToken, baseUrl: rec.baseUrl },
      clientId,
      grantedScopes,
    );
    this.store.revoke(refreshToken); // rotate
    return this.tokenResponse(accessToken, newRefresh, grantedScopes);
  }

  verifyAccessToken(token: string): AuthInfo {
    const rec = this.store.getAccess(token);
    if (!rec) throw new InvalidTokenError("unknown or expired access token");
    return {
      token,
      clientId: rec.clientId,
      scopes: rec.scopes,
      expiresAt: Math.floor(rec.expiresAt / 1000),
      // The bound NetBird credential travels here; resolveBinding unwraps it.
      extra: { netbirdToken: rec.netbirdToken, baseUrl: rec.baseUrl },
    };
  }

  /**
   * Resolve a Bearer access token straight to the NetBird credential it's bound
   * to. Wraps verifyAccessToken so the untyped `extra` bag it returns never
   * crosses this seam — callers only ever see AuthContext.
   */
  resolveBinding(bearerToken: string): AuthContext {
    let info: AuthInfo;
    try {
      info = this.verifyAccessToken(bearerToken);
    } catch {
      throw new AuthError("Invalid or expired access token.", "unknown_token");
    }
    const binding = info.extra as unknown as NetBirdBinding | undefined;
    if (!binding?.netbirdToken || !binding.baseUrl) {
      throw new AuthError("Invalid or expired access token.", "unknown_token");
    }
    return { token: binding.netbirdToken, baseUrl: binding.baseUrl };
  }

  /** Revoke on behalf of the requesting client (RFC 7009); other clients' tokens are left untouched. */
  revoke(token: string, clientId: string): void {
    this.store.revokeForClient(token, clientId);
  }

  private tokenResponse(accessToken: string, refreshToken: string, scopes: string[]): OAuthTokens {
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      refresh_token: refreshToken,
      ...(scopes.length ? { scope: scopes.join(" ") } : {}),
    };
  }

  /**
   * Delegates PAT verification to a short-lived NetBird client so the auth
   * header convention, timeout, retry, and rate limiting have exactly one
   * implementation — the same one every tool call uses.
   */
  private async checkPat(pat: string, baseUrl: string, sourceKey: string): Promise<TokenVerification> {
    // Take the per-source slot first: a source over its share stalls here on its
    // own limiter without ever consuming a slot in the shared global limiter, so
    // other sources' verifications still get through.
    await this.verifySourceLimiters.get(sourceKey).acquire();
    return verifyPat(
      { token: pat, baseUrl },
      {
        logger: this.logger,
        rateLimiter: this.verifyLimiter,
        timeoutMs: this.timeoutMs,
        fetchImpl: this.fetchImpl,
      },
    );
  }
}

/**
 * Recompute the S256 code challenge from the supplied verifier and compare it,
 * in constant time, to the challenge bound to the authorization code. A missing
 * verifier never matches. This is the module-internal PKCE re-check the exchange
 * runs so PKCE cannot be silently skipped regardless of SDK call order.
 */
function pkceMatches(codeVerifier: string | undefined, storedChallenge: string): boolean {
  if (!codeVerifier) return false;
  const computed = createHash("sha256").update(codeVerifier).digest("base64url");
  const a = Buffer.from(computed);
  const b = Buffer.from(storedChallenge);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
