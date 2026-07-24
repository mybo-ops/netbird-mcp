import type { Request, Response } from "express";
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { Logger } from "../logger.js";
import type { AuthContext } from "../auth/context.js";
import {
  OAuthCore,
  type OAuthCoreOptions,
  type OAuthChallenge,
  type OAuthLoginError,
} from "./core.js";
import { renderLoginPage } from "./loginPage.js";

export type ProviderOptions = OAuthCoreOptions;

/**
 * OAuth 2.1 authorization server for the NetBird connector. Thin web adapter:
 * it maps HTTP req/res to the core's decision inputs and results, and holds no
 * validation, protocol state, or escaping logic of its own — all of that lives
 * in OAuthCore. This class exists only to satisfy the MCP SDK's
 * OAuthServerProvider interface and to render the pages the core decides on.
 *
 * v2 upgrade: swap the login step for an upstream IdP redirect (real SSO) and
 * bind the resulting NetBird OAuth token instead of a PAT — only the core's
 * completeLogin changes; this adapter and the token protocol don't.
 */
export class NetBirdOAuthProvider implements OAuthServerProvider {
  private readonly core: OAuthCore;
  private readonly logger: Logger;

  /**
   * The core verifies PKCE itself inside exchangeAuthorizationCode. This flag
   * tells the SDK's token handler to hand the code_verifier through instead of
   * validating locally — without it the SDK passes `undefined` and every
   * legitimate exchange would fail the core's mandatory PKCE check.
   */
  readonly skipLocalPkceValidation = true;

  constructor(opts: ProviderOptions) {
    this.logger = opts.logger;
    this.core = new OAuthCore(opts);
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (id) => this.core.getClient(id),
      registerClient: (client) => {
        const full = client as OAuthClientInformationFull;
        this.core.registerClient(full);
        this.logger.info("oauth client registered", { client_id: full.client_id });
        return full;
      },
    };
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    const decision = this.core.beginAuthorize({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state,
      scopes: params.scopes,
      resource: params.resource?.toString(),
    });
    this.sendPage(res, decision);
  }

  /**
   * Handles the login form submission (mounted as POST /oauth/netbird-login).
   * Not part of the OAuthServerProvider interface — it's our interactive step.
   */
  handleLogin = async (req: Request, res: Response): Promise<void> => {
    const body = req.body as Record<string, string>;
    // Key per-source verify throttling on the client IP (honours Express
    // `trust proxy`); fall through to the core's own default when it's absent.
    const decision = await this.core.completeLogin(
      {
        clientId: body.client_id,
        redirectUri: body.redirect_uri,
        state: body.state,
        codeChallenge: body.code_challenge,
        scope: body.scope,
        resource: body.resource,
        netbirdToken: body.netbird_token,
        netbirdApiUrl: body.netbird_api_url,
      },
      req.ip,
    );
    if (decision.kind === "redirect") {
      res.redirect(302, decision.location);
      return;
    }
    this.sendPage(res, decision);
  };

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    return this.core.challengeForCode(authorizationCode);
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    return this.core.exchangeAuthorizationCode(
      client.client_id,
      authorizationCode,
      codeVerifier,
      redirectUri,
    );
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    return this.core.exchangeRefreshToken(client.client_id, refreshToken, scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    return this.core.verifyAccessToken(token);
  }

  /** Wraps the core's binding resolution; see OAuthCore.resolveBinding for the seam it protects. */
  async resolveBinding(bearerToken: string): Promise<AuthContext> {
    return this.core.resolveBinding(bearerToken);
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: { token: string },
  ): Promise<void> {
    // RFC 7009: a client may only revoke its own tokens. The core no-ops (still
    // reporting success) when the token belongs to a different client.
    this.core.revoke(request.token, client.client_id);
  }

  /**
   * Renders whatever page a login-challenge or login-error decision calls for.
   * The decision is already structurally a LoginPageParams (its challenge/error
   * types are `{ kind } & LoginPrefill`, and LoginPrefill = LoginPageParams), so
   * it is handed straight to the renderer — renderLoginPage reads only the
   * prefill fields and ignores the discriminant.
   */
  private sendPage(res: Response, decision: OAuthChallenge | OAuthLoginError): void {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    if (decision.kind === "error") {
      res.status(400).send(renderLoginPage(decision, decision.reason));
      return;
    }
    res.send(renderLoginPage(decision));
  }
}
