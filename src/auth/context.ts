/**
 * AuthContext is the single seam that lets one server run locally and in the cloud.
 * Local resolves it once from env; the cloud entrypoint resolves it per request
 * from an inbound header. In v2 the request resolver can be swapped for an OAuth2
 * exchange without touching any tool code.
 */
export interface AuthContext {
  /** NetBird Personal Access Token — sent as `Authorization: Token <token>`. */
  token: string;
  /** Fully-qualified NetBird API base URL, no trailing slash. */
  baseUrl: string;
}

/** Machine-readable reason for an AuthError, for transports to map uniformly. */
export type AuthErrorCode =
  | "missing_credentials"
  | "unknown_token"
  | "wrong_scheme"
  | "oauth_disabled"
  /** The direct-PAT header path is turned off (NETBIRD_ENABLE_DIRECT_PAT). */
  | "direct_pat_disabled"
  /** The caller-supplied NetBird base URL is not on the host allowlist. */
  | "forbidden_host"
  /** The presented direct PAT was rejected by NetBird (401/403). */
  | "invalid_token";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(message: string, code: AuthErrorCode = "missing_credentials") {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}
