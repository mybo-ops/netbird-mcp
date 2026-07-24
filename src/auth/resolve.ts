import type { IncomingHttpHeaders } from "node:http";
import type { NetBirdOAuthProvider } from "../oauth/provider.js";
import type { TokenVerification } from "../netbird/client.js";
import { checkApiUrl } from "../netbird/apiUrlPolicy.js";
import { authFromRequest, headerValue, RequestAuthOptions } from "./fromRequest.js";
import { AuthContext, AuthError } from "./context.js";

export interface AuthResolutionOptions extends RequestAuthOptions {
  /** Pass only when OAuth is enabled; Bearer tokens then resolve through it. */
  provider?: NetBirdOAuthProvider;
  /**
   * Hosts the caller-supplied base URL may target — the resolved
   * config.allowedApiHosts. The direct-PAT path is checked against this before
   * any outbound NetBird call, so a request can never steer the server at an
   * arbitrary host.
   */
  allowedApiHosts: readonly string[];
  /**
   * Whether the direct-PAT header path is available at all
   * (config.http.directPatEnabled). Off by default when OAuth is enabled.
   */
  directPatEnabled: boolean;
  /**
   * Verify a direct PAT against NetBird before it is trusted. "invalid" (401/403)
   * is rejected; "unknown" (timeout / network / 5xx) is allowed through — the host
   * is already allowlisted and NetBird refuses a bogus token on the real call, so
   * an indeterminate check must not lock out a legitimate token.
   */
  verifyPat: (auth: AuthContext) => Promise<TokenVerification>;
}

const BEARER_RE = /^Bearer\s+/i;

/**
 * Resolve a request to a trustworthy NetBird AuthContext, or throw AuthError.
 * The single place that decides how a request authenticates:
 *
 *   1. OAuth 2.1 (what Claude uses): `Authorization: Bearer <token>`, resolved
 *      through the provider's typed binding lookup. The bound credential was
 *      verified when the user logged in, so nothing more is checked here.
 *   2. Direct PAT (a fallback for testing / simple deploys): the dedicated token
 *      header or `Authorization: Token <pat>`. This path is only taken when it is
 *      explicitly enabled, and before the credential is trusted its base URL is
 *      checked against the host allowlist and the PAT is verified against NetBird.
 *
 * Bearer is reserved for OAuth: with no provider it falls through to the
 * direct-PAT path, which rejects it — tagged "oauth_disabled" so the reason is
 * specific.
 */
export async function resolveAuth(
  headers: IncomingHttpHeaders,
  opts: AuthResolutionOptions,
): Promise<AuthContext> {
  const authz = headerValue(headers, "authorization");
  const bearerAttempted = authz !== undefined && BEARER_RE.test(authz);

  // 1. OAuth path — the bound credential was already verified at login.
  if (bearerAttempted && opts.provider) {
    const token = authz!.replace(BEARER_RE, "").trim();
    return opts.provider.resolveBinding(token);
  }

  // 2. Direct-PAT path is opt-in; when it's off, refuse before touching headers.
  if (!opts.directPatEnabled) {
    throw new AuthError(
      bearerAttempted
        ? "OAuth is not available and direct-PAT authentication is disabled on this server."
        : "Direct-PAT authentication is disabled on this server. Use the OAuth flow.",
      bearerAttempted ? "oauth_disabled" : "direct_pat_disabled",
    );
  }

  let ctx: AuthContext;
  try {
    ctx = authFromRequest(headers, opts);
  } catch (err) {
    if (bearerAttempted && err instanceof AuthError) {
      throw new AuthError(err.message, "oauth_disabled");
    }
    throw err;
  }

  // 3. Gate the caller-supplied base URL before any outbound request is made.
  const urlCheck = checkApiUrl(ctx.baseUrl, opts.allowedApiHosts);
  if (!urlCheck.allowed) {
    throw new AuthError(`NetBird API URL rejected: ${urlCheck.reason}.`, "forbidden_host");
  }

  // 4. Verify the PAT before trusting the caller and building anything downstream.
  if ((await opts.verifyPat(ctx)) === "invalid") {
    throw new AuthError("The NetBird token was rejected (401/403).", "invalid_token");
  }

  return ctx;
}
