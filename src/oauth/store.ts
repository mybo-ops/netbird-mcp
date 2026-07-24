import { randomBytes } from "node:crypto";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

/**
 * In-memory OAuth state. Fine for a prototype / single instance. For production,
 * back these with a shared, encrypted store (e.g. Redis) so tokens survive
 * restarts and work across replicas, and so the bound NetBird PAT is at rest
 * encrypted.
 */

/** What a Claude access/refresh token maps to: the tenant's NetBird credential. */
export interface NetBirdBinding {
  netbirdToken: string;
  baseUrl: string;
}

interface CodeRecord extends NetBirdBinding {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  expiresAt: number;
}

interface AccessRecord extends NetBirdBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
}

interface RefreshRecord extends NetBirdBinding {
  clientId: string;
  scopes: string[];
  expiresAt: number;
}

const CODE_TTL_MS = 5 * 60_000; // authorization codes are short-lived
export const ACCESS_TTL_SECONDS = 60 * 60; // 1 hour
// Refresh tokens outlive access tokens but not forever: OAuth 2.1 wants a bounded
// lifetime so a leaked, never-rotated refresh token can't mint access tokens
// indefinitely. Rotation (see exchangeRefreshToken) resets this window per issue.
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

function token(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

/** Look up a record, dropping (and reporting absent) one that has passed its expiry. */
function getLive<T extends { expiresAt: number }>(
  map: Map<string, T>,
  key: string,
): T | undefined {
  const rec = map.get(key);
  if (!rec) return undefined;
  if (rec.expiresAt < Date.now()) {
    map.delete(key);
    return undefined;
  }
  return rec;
}

export class OAuthStore {
  private readonly clients = new Map<string, OAuthClientInformationFull>();
  private readonly codes = new Map<string, CodeRecord>();
  private readonly access = new Map<string, AccessRecord>();
  private readonly refresh = new Map<string, RefreshRecord>();

  // --- clients (dynamic registration) ---
  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }
  saveClient(client: OAuthClientInformationFull): void {
    this.clients.set(client.client_id, client);
  }

  // --- authorization codes ---
  createCode(rec: Omit<CodeRecord, "expiresAt">): string {
    const code = token("nbmcp_ac");
    this.codes.set(code, { ...rec, expiresAt: Date.now() + CODE_TTL_MS });
    return code;
  }
  takeCode(code: string): CodeRecord | undefined {
    const rec = this.codes.get(code);
    this.codes.delete(code); // one-time use
    if (!rec || rec.expiresAt < Date.now()) return undefined;
    return rec;
  }
  challengeForCode(code: string): string | undefined {
    return this.codes.get(code)?.codeChallenge;
  }

  // --- access + refresh tokens ---
  issueTokens(binding: NetBirdBinding, clientId: string, scopes: string[]) {
    const accessToken = token("nbmcp_at");
    const refreshToken = token("nbmcp_rt");
    this.access.set(accessToken, {
      ...binding,
      clientId,
      scopes,
      expiresAt: Date.now() + ACCESS_TTL_SECONDS * 1000,
    });
    this.refresh.set(refreshToken, {
      ...binding,
      clientId,
      scopes,
      expiresAt: Date.now() + REFRESH_TTL_SECONDS * 1000,
    });
    return { accessToken, refreshToken };
  }

  getAccess(accessToken: string): AccessRecord | undefined {
    return getLive(this.access, accessToken);
  }

  getRefresh(refreshToken: string): RefreshRecord | undefined {
    return getLive(this.refresh, refreshToken);
  }

  /** Unconditional delete — used internally for refresh-token rotation. */
  revoke(token: string): void {
    this.access.delete(token);
    this.refresh.delete(token);
  }

  /**
   * Revoke a token on behalf of a specific client (RFC 7009): delete it only if
   * it belongs to that client. A token owned by another client — or one that
   * doesn't exist — is left untouched; the caller still reports success, so a
   * client can neither kill another's tokens nor probe which tokens exist.
   */
  revokeForClient(token: string, clientId: string): void {
    const accessRec = this.access.get(token);
    if (accessRec) {
      if (accessRec.clientId === clientId) this.access.delete(token);
      return;
    }
    const refreshRec = this.refresh.get(token);
    if (refreshRec && refreshRec.clientId === clientId) this.refresh.delete(token);
  }
}
