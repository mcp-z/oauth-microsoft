/**
 * Loopback OAuth Implementation for Microsoft (RFC 8252)
 *
 * Implements OAuth 2.0 Authorization Code Flow with PKCE using loopback interface redirection.
 * Uses ephemeral local server with OS-assigned port (RFC 8252 Section 8.3).
 * Eliminates port conflicts by using port 0, allowing unlimited concurrent servers.
 *
 * Flow:
 * 1. Check token cache (memory + storage)
 * 2. If cache miss: Start ephemeral server on port 0
 * 3. Generate auth URL with dynamic redirect (localhost:{assigned-port})
 * 4. Open browser or print URL (headless flag controls behavior)
 * 5. Handle callback, exchange code for token
 * 6. Cache token to storage
 * 7. Close ephemeral server
 *
 * CHANGE (2026-01-03):
 * - Non-headless mode now opens the auth URL AND blocks (polls) until tokens are available,
 *   for BOTH redirectUri (persistent) and ephemeral (loopback) modes.
 * - Ephemeral flow no longer calls `open()` itself. Instead it:
 *   1) starts the loopback callback server
 *   2) throws AuthRequiredError(auth_url)
 * - Middleware catches AuthRequiredError(auth_url):
 *   - if not headless: open(url) once + poll pending state until callback completes (or timeout)
 *   - then retries token acquisition and injects authContext in the SAME tool call.
 */

import { addAccount, generatePKCE, getActiveAccount, getErrorTemplate, getSuccessTemplate, getToken, type OAuth2TokenStorageProvider, setAccountInfo, setActiveAccount, setToken } from '@mcp-z/oauth';
import { randomUUID } from 'crypto';
import * as http from 'http';
import open from 'open';
import { fetchWithTimeout } from '../lib/fetch-with-timeout.ts';
import { type AuthContext, type AuthFlowDescriptor, AuthRequiredError, type CachedToken, type EnrichedExtra, type LoopbackOAuthConfig } from '../types.ts';

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

type PendingAuth = {
  codeVerifier: string;
  createdAt: number;
  // populated when callback completes successfully
  completedAt?: number;
  email?: string;
};

const OAUTH_TIMEOUT_MS = 5 * 60 * 1000;
const OAUTH_POLL_MS = 500;

/**
 * Loopback OAuth Client (RFC 8252 Section 7.3)
 *
 * Implements OAuth 2.0 Authorization Code Flow with PKCE for native applications
 * using loopback interface redirection. Manages ephemeral OAuth flows and token persistence
 * with Keyv for key-based token storage using compound keys.
 *
 * Token key format: {accountId}:{service}:token (e.g., "user@example.com:outlook:token")
 */
export class LoopbackOAuthProvider implements OAuth2TokenStorageProvider {
  private config: LoopbackOAuthConfig;

  // Track URLs we've already opened for a given state within this process (prevents tab spam).
  private openedStates = new Set<string>();

  constructor(config: LoopbackOAuthConfig) {
    this.config = config;
  }

  /**
   * Get access token from Keyv using compound key
   *
   * @param accountId - Account identifier (email address). Required for loopback OAuth.
   * @returns Access token for API requests
   */
  async getAccessToken(accountId?: string): Promise<string> {
    const { logger, service, tokenStore } = this.config;

    // Use active account if no accountId specified
    const effectiveAccountId = accountId ?? (await getActiveAccount(tokenStore, { service }));

    // If we have an accountId, try to use existing token
    if (effectiveAccountId) {
      logger.debug('Getting access token', { service, accountId: effectiveAccountId });

      // Check Keyv for token using new key format
      const storedToken = await getToken<CachedToken>(tokenStore, { accountId: effectiveAccountId, service });

      if (storedToken && this.isTokenValid(storedToken)) {
        logger.debug('Using stored access token', { accountId: effectiveAccountId });
        return storedToken.accessToken;
      }

      // If stored token expired but has refresh token, try refresh
      if (storedToken?.refreshToken) {
        try {
          logger.info('Refreshing expired access token', { accountId: effectiveAccountId });
          const refreshedToken = await this.refreshAccessToken(storedToken.refreshToken);
          await setToken(tokenStore, { accountId: effectiveAccountId, service }, refreshedToken);
          return refreshedToken.accessToken;
        } catch (error) {
          logger.info('Token refresh failed, starting new OAuth flow', {
            accountId: effectiveAccountId,
            error: error instanceof Error ? error.message : String(error),
          });
          // Fall through to new OAuth flow
        }
      }
    }

    const { clientId, tenantId, scope, redirectUri } = this.config;

    if (redirectUri) {
      // Persistent callback mode (cloud deployment with configured redirect_uri)
      const { verifier: codeVerifier, challenge: codeChallenge } = generatePKCE();
      const stateId = randomUUID();

      // Store PKCE verifier for callback (5 minute TTL)
      await this.createPendingAuth({ state: stateId, codeVerifier });

      // Build auth URL with configured redirect_uri
      const authUrl = this.buildAuthUrl({
        tenantId,
        clientId,
        redirectUri,
        scope,
        codeChallenge,
        state: stateId,
      });

      logger.info('OAuth required - persistent callback mode', { service, redirectUri });
      throw new AuthRequiredError({
        kind: 'auth_url',
        provider: service,
        url: authUrl,
      });
    }

    // Ephemeral callback mode (local development)
    logger.info('Starting ephemeral OAuth flow', { service, headless: this.config.headless });
    const descriptor = await this.startEphemeralOAuthFlow();
    throw new AuthRequiredError(descriptor);
  }

  /**
   * Convert to Microsoft Graph-compatible auth provider
   *
   * @param accountId - Account identifier for multi-account support (e.g., 'user@example.com')
   * @returns Auth provider configured for the specified account
   */
  toAuthProvider(accountId?: string): { getAccessToken: () => Promise<string> } {
    // Capture accountId in closure to pass to getAccessToken
    const getToken = () => this.getAccessToken(accountId);

    return {
      getAccessToken: getToken,
    };
  }

  /**
   * Get user email from Microsoft Graph API (pure query)
   * Used to query email for existing authenticated account
   *
   * @param accountId - Account identifier to get email for
   * @returns User's email address
   */
  async getUserEmail(accountId?: string): Promise<string> {
    // Get token for existing account
    const token = await this.getAccessToken(accountId);

    // Fetch email from Microsoft Graph
    const response = await fetchWithTimeout('https://graph.microsoft.com/v1.0/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.status} ${await response.text()}`);
    }

    const userInfo = (await response.json()) as { mail?: string; userPrincipalName: string };
    return userInfo.mail ?? userInfo.userPrincipalName;
  }

  private isTokenValid(token: CachedToken): boolean {
    if (!token.expiresAt) return true; // No expiry = assume valid
    return Date.now() < token.expiresAt - 60000; // 1 minute buffer
  }

  /**
   * Fetch user email from Microsoft Graph using access token
   * Called during OAuth flow to get email for accountId
   *
   * @param accessToken - Fresh access token from OAuth exchange
   * @returns User's email address (mail field or userPrincipalName fallback)
   */
  private async fetchUserEmailFromToken(accessToken: string): Promise<string> {
    const { logger } = this.config;

    const response = await fetchWithTimeout('https://graph.microsoft.com/v1.0/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to fetch user email: HTTP ${response.status} - ${errorText}`);
    }

    const userInfo = (await response.json()) as { mail?: string; userPrincipalName: string };
    const email = userInfo.mail ?? userInfo.userPrincipalName;

    logger.debug('Fetched user email from Graph API', { email });
    return email;
  }

  // ---------------------------------------------------------------------------
  // Shared OAuth helpers
  // ---------------------------------------------------------------------------

  /**
   * Build Microsoft OAuth authorization URL with the "most parameters" baseline.
   * This is shared by BOTH persistent (redirectUri) and ephemeral (loopback) modes.
   */
  private buildAuthUrl(args: { tenantId: string; clientId: string; redirectUri: string; scope: string; codeChallenge: string; state: string }): string {
    const authUrl = new URL(`https://login.microsoftonline.com/${args.tenantId}/oauth2/v2.0/authorize`);
    authUrl.searchParams.set('client_id', args.clientId);
    authUrl.searchParams.set('redirect_uri', args.redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', args.scope);

    // Keep response_mode consistent across both modes (most-params baseline)
    authUrl.searchParams.set('response_mode', 'query');

    // PKCE
    authUrl.searchParams.set('code_challenge', args.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // State (required in both modes)
    authUrl.searchParams.set('state', args.state);

    // Keep current behavior
    authUrl.searchParams.set('prompt', 'select_account');

    return authUrl.toString();
  }

  /**
   * Create a cached token + email from an authorization code.
   * This is the shared callback handler for BOTH persistent and ephemeral modes.
   */
  private async handleAuthorizationCode(args: { code: string; codeVerifier: string; redirectUri: string }): Promise<{ email: string; token: CachedToken }> {
    // Exchange code for token (must use same redirect_uri as in authorization request)
    const tokenResponse = await this.exchangeCodeForToken(args.code, args.codeVerifier, args.redirectUri);

    // Build cached token
    const cachedToken: CachedToken = {
      accessToken: tokenResponse.access_token,
      ...(tokenResponse.refresh_token !== undefined && { refreshToken: tokenResponse.refresh_token }),
      ...(tokenResponse.expires_in !== undefined && { expiresAt: Date.now() + tokenResponse.expires_in * 1000 }),
      ...(tokenResponse.scope !== undefined && { scope: tokenResponse.scope }),
    };

    // Fetch user email immediately using the new access token
    const email = await this.fetchUserEmailFromToken(tokenResponse.access_token);

    return { email, token: cachedToken };
  }

  /**
   * Store token + account metadata. Shared by BOTH persistent and ephemeral modes.
   */
  private async persistAuthResult(args: { email: string; token: CachedToken }): Promise<void> {
    const { tokenStore, service } = this.config;

    await setToken(tokenStore, { accountId: args.email, service }, args.token);
    await addAccount(tokenStore, { service, accountId: args.email });
    await setActiveAccount(tokenStore, { service, accountId: args.email });
    await setAccountInfo(tokenStore, { service, accountId: args.email }, { email: args.email, addedAt: new Date().toISOString() });
  }

  /**
   * Pending auth (PKCE verifier) key format.
   */
  private pendingKey(state: string): string {
    return `${this.config.service}:pending:${state}`;
  }

  /**
   * Store PKCE verifier for callback (5 minute TTL).
   * Shared by BOTH persistent and ephemeral modes.
   */
  private async createPendingAuth(args: { state: string; codeVerifier: string }): Promise<void> {
    const { tokenStore } = this.config;
    const record: PendingAuth = { codeVerifier: args.codeVerifier, createdAt: Date.now() };
    await tokenStore.set(this.pendingKey(args.state), record, OAUTH_TIMEOUT_MS);
  }

  /**
   * Load and validate pending auth state (5 minute TTL).
   * Shared by BOTH persistent and ephemeral modes.
   */
  private async readAndValidatePendingAuth(state: string): Promise<PendingAuth> {
    const { tokenStore } = this.config;

    const pendingAuth = await tokenStore.get<PendingAuth>(this.pendingKey(state));
    if (!pendingAuth) {
      throw new Error('Invalid or expired OAuth state. Please try again.');
    }

    // Check TTL (5 minutes)
    if (Date.now() - pendingAuth.createdAt > OAUTH_TIMEOUT_MS) {
      await tokenStore.delete(this.pendingKey(state));
      throw new Error('OAuth state expired. Please try again.');
    }

    return pendingAuth;
  }

  /**
   * Mark pending auth as completed (used by middleware polling).
   */
  private async markPendingComplete(args: { state: string; email: string; pending: PendingAuth }): Promise<void> {
    const { tokenStore } = this.config;
    const updated: PendingAuth = {
      ...args.pending,
      completedAt: Date.now(),
      email: args.email,
    };
    await tokenStore.set(this.pendingKey(args.state), updated, OAUTH_TIMEOUT_MS);
  }

  /**
   * Clean up pending auth state.
   */
  private async deletePendingAuth(state: string): Promise<void> {
    const { tokenStore } = this.config;
    await tokenStore.delete(this.pendingKey(state));
  }

  /**
   * Wait until pending auth is marked completed (or timeout).
   * Used by middleware after opening auth URL in non-headless mode.
   */
  private async waitForOAuthCompletion(state: string): Promise<{ email?: string }> {
    const { tokenStore } = this.config;
    const key = this.pendingKey(state);
    const start = Date.now();

    while (Date.now() - start < OAUTH_TIMEOUT_MS) {
      const pending = await tokenStore.get<PendingAuth>(key);
      if (pending?.completedAt) {
        return { email: pending.email };
      }
      await new Promise((r) => setTimeout(r, OAUTH_POLL_MS));
    }

    throw new Error('OAuth flow timed out after 5 minutes');
  }

  /**
   * Process an OAuth callback using shared state validation + token exchange + persistence.
   * Used by BOTH:
   * - ephemeral loopback server callback handler
   * - persistent redirectUri callback handler
   *
   * IMPORTANT CHANGE:
   * - We do NOT delete pending state here anymore.
   * - We mark it completed so middleware can poll and then clean it up.
   */
  private async processOAuthCallback(args: { code: string; state: string; redirectUri: string }): Promise<{ email: string; token: CachedToken }> {
    const { logger, service } = this.config;

    const pending = await this.readAndValidatePendingAuth(args.state);

    logger.info('Processing OAuth callback', { service, state: args.state });

    const result = await this.handleAuthorizationCode({
      code: args.code,
      codeVerifier: pending.codeVerifier,
      redirectUri: args.redirectUri,
    });

    await this.persistAuthResult(result);
    await this.markPendingComplete({ state: args.state, email: result.email, pending });

    logger.info('OAuth callback completed', { service, email: result.email });
    return result;
  }

  // ---------------------------------------------------------------------------
  // Ephemeral loopback server + flow
  // ---------------------------------------------------------------------------

  /**
   * Loopback OAuth server helper (RFC 8252 Section 7.3)
   *
   * Implements ephemeral local server with OS-assigned port (RFC 8252 Section 8.3).
   * Shared callback handling uses:
   * - the same authUrl builder as redirectUri mode
   * - the same pending PKCE verifier storage as redirectUri mode
   * - the same callback processor as redirectUri mode
   */
  private createOAuthCallbackServer(args: {
    callbackPath: string;
    finalRedirectUri: () => string; // resolved after listen
    onDone: () => void;
    onError: (err: unknown) => void;
  }): http.Server {
    const { logger } = this.config;

    // Create ephemeral server with OS-assigned port (RFC 8252)
    return http.createServer(async (req, res) => {
      try {
        if (!req.url) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate('Invalid request'));
          args.onError(new Error('Invalid request: missing URL'));
          return;
        }

        // Use loopback base for URL parsing (port is not important for parsing path/query)
        const url = new URL(req.url, 'http://127.0.0.1');

        if (url.pathname !== args.callbackPath) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
          return;
        }

        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');
        const state = url.searchParams.get('state');

        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate(error));
          args.onError(new Error(`OAuth error: ${error}`));
          return;
        }

        if (!code) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate('No authorization code received'));
          args.onError(new Error('No authorization code received'));
          return;
        }

        if (!state) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate('Missing state parameter in OAuth callback'));
          args.onError(new Error('Missing state parameter in OAuth callback'));
          return;
        }

        try {
          await this.processOAuthCallback({
            code,
            state,
            redirectUri: args.finalRedirectUri(),
          });

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(getSuccessTemplate());

          args.onDone();
        } catch (exchangeError) {
          logger.error('Token exchange failed', { error: exchangeError instanceof Error ? exchangeError.message : String(exchangeError) });
          res.writeHead(500, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate('Token exchange failed'));
          args.onError(exchangeError);
        }
      } catch (outerError) {
        logger.error('OAuth callback server error', { error: outerError instanceof Error ? outerError.message : String(outerError) });
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end(getErrorTemplate('Internal server error'));
        args.onError(outerError);
      }
    });
  }

  /**
   * Starts the ephemeral loopback server and returns an AuthRequiredError(auth_url).
   * Middleware will open+poll and then retry in the same call.
   */
  private async startEphemeralOAuthFlow(): Promise<AuthFlowDescriptor> {
    const { clientId, tenantId, scope, headless, logger, redirectUri: configRedirectUri, service, tokenStore } = this.config;

    // Server listen configuration (where ephemeral server binds)
    let listenHost = 'localhost'; // Default: localhost for ephemeral loopback
    let listenPort = 0; // Default: OS-assigned ephemeral port

    // Redirect URI configuration (what goes in auth URL and token exchange)
    let callbackPath = '/callback'; // Default callback path
    let useConfiguredUri = false;

    if (configRedirectUri) {
      try {
        const parsed = new URL(configRedirectUri);
        const isLoopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

        if (isLoopback) {
          // Local development: Listen on specific loopback address/port
          listenHost = parsed.hostname;
          listenPort = parsed.port ? Number.parseInt(parsed.port, 10) : 0;
        } else {
          // Cloud deployment: Listen on 0.0.0.0 with PORT from environment
          // The redirectUri is the PUBLIC URL (e.g., https://example.com/oauth/callback)
          // The server listens on 0.0.0.0:PORT and the load balancer routes to it
          listenHost = '0.0.0.0';
          const envPort = process.env.PORT ? Number.parseInt(process.env.PORT, 10) : undefined;
          listenPort = envPort && Number.isFinite(envPort) ? envPort : 8080;
        }

        // Extract callback path from URL
        if (parsed.pathname && parsed.pathname !== '/') {
          callbackPath = parsed.pathname;
        }

        useConfiguredUri = true;

        logger.debug('Using configured redirect URI', {
          listenHost,
          listenPort,
          callbackPath,
          redirectUri: configRedirectUri,
          isLoopback,
        });
      } catch (error) {
        logger.warn('Failed to parse redirectUri, using ephemeral defaults', {
          redirectUri: configRedirectUri,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue with defaults (localhost, port 0, http, /callback)
      }
    }

    // Generate PKCE challenge + state
    const { verifier: codeVerifier, challenge: codeChallenge } = generatePKCE();
    const stateId = randomUUID();

    // Store PKCE verifier for callback (5 minute TTL)
    await this.createPendingAuth({ state: stateId, codeVerifier });

    let server: http.Server | null = null;
    let serverPort: number;
    let finalRedirectUri: string; // set after listen

    // Create ephemeral server with OS-assigned port (RFC 8252)
    server = this.createOAuthCallbackServer({
      callbackPath,
      finalRedirectUri: () => finalRedirectUri,
      onDone: () => {
        server?.close();
      },
      onError: (err) => {
        logger.error('Ephemeral OAuth server error', { error: err instanceof Error ? err.message : String(err) });
        server?.close();
      },
    });

    // Start listening
    await new Promise<void>((resolve, reject) => {
      server?.listen(listenPort, listenHost, () => {
        const address = server?.address();
        if (!address || typeof address === 'string') {
          server?.close();
          reject(new Error('Failed to start ephemeral server'));
          return;
        }

        serverPort = address.port;

        // Construct final redirect URI
        if (useConfiguredUri && configRedirectUri) {
          finalRedirectUri = configRedirectUri;
        } else {
          finalRedirectUri = `http://localhost:${serverPort}${callbackPath}`;
        }

        logger.info('Ephemeral OAuth server started', { port: serverPort, headless, service });

        resolve();
      });
    });

    // Timeout after 5 minutes (match middleware polling timeout)
    setTimeout(() => {
      if (server) {
        server.close();
        // Best-effort cleanup if user never completes flow:
        // delete pending so a future attempt can restart cleanly.
        void tokenStore.delete(this.pendingKey(stateId));
      }
    }, OAUTH_TIMEOUT_MS);

    // Build auth URL - SAME helper as persistent mode
    const authUrl = this.buildAuthUrl({
      tenantId,
      clientId,
      redirectUri: finalRedirectUri,
      scope,
      codeChallenge,
      state: stateId,
    });

    return {
      kind: 'auth_url',
      provider: service,
      url: authUrl,
    };
  }

  private async exchangeCodeForToken(code: string, codeVerifier: string, redirectUri: string): Promise<TokenResponse> {
    const { clientId, clientSecret, tenantId } = this.config;

    const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const params: Record<string, string> = {
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code_verifier: codeVerifier,
    };

    // Only include client_secret for confidential clients
    if (clientSecret) {
      params.client_secret = clientSecret;
    }

    const body = new URLSearchParams(params);

    const response = await fetchWithTimeout(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
    }

    return (await response.json()) as TokenResponse;
  }

  private async refreshAccessToken(refreshToken: string): Promise<CachedToken> {
    const { clientId, clientSecret, tenantId } = this.config;

    const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const params: Record<string, string> = {
      refresh_token: refreshToken,
      client_id: clientId,
      grant_type: 'refresh_token',
    };

    // Only include client_secret for confidential clients
    if (clientSecret) {
      params.client_secret = clientSecret;
    }

    // NOTE: We intentionally do NOT include "scope" in refresh requests.

    const body = new URLSearchParams(params);

    const response = await fetchWithTimeout(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed: ${response.status} ${errorText}`);
    }

    const tokenResponse = (await response.json()) as TokenResponse;

    return {
      accessToken: tokenResponse.access_token,
      refreshToken: refreshToken, // Keep original refresh token
      ...(tokenResponse.expires_in !== undefined && { expiresAt: Date.now() + tokenResponse.expires_in * 1000 }),
      ...(tokenResponse.scope !== undefined && { scope: tokenResponse.scope }),
    };
  }

  /**
   * Handle OAuth callback from persistent endpoint.
   * Used by HTTP servers with configured redirectUri.
   *
   * @param params - OAuth callback parameters
   * @returns Email and cached token
   */
  async handleOAuthCallback(params: { code: string; state?: string }): Promise<{ email: string; token: CachedToken }> {
    const { code, state } = params;
    const { redirectUri } = this.config;

    if (!state) {
      throw new Error('Missing state parameter in OAuth callback');
    }

    if (!redirectUri) {
      throw new Error('handleOAuthCallback requires configured redirectUri');
    }

    // Shared callback processor (same code path as ephemeral)
    return await this.processOAuthCallback({ code, state, redirectUri });
  }

  /**
   * Create auth middleware for single-user context (single active account per service)
   *
   * Single-user mode:
   * - Maintains per-service active accounts in storage
   * - Supports backchannel account override via extra._meta.accountId
   * - Automatically enhances output schemas with auth_required branch
   *
   * Example:
   * ```typescript
   * const loopback = new LoopbackOAuthProvider({ service: 'outlook', ... });
   * const middleware = loopback.authMiddleware();
   * const tools = toolFactories.map(f => f()).map(middleware.withToolAuth);
   * const resources = resourceFactories.map(f => f()).map(middleware.withResourceAuth);
   * const prompts = promptFactories.map(f => f()).map(middleware.withPromptAuth);
   * ```
   *
   * @returns Object with withToolAuth, withResourceAuth, withPromptAuth methods
   */
  authMiddleware() {
    const { service, tokenStore, logger } = this.config;

    // Shared wrapper logic - extracts extra parameter from specified position
    // Generic T captures the actual module type; handler is cast from unknown to callable
    const wrapAtPosition = <T extends { name: string; handler: unknown; [key: string]: unknown }>(module: T, extraPosition: number): T => {
      const operation = module.name;
      const originalHandler = module.handler as (...args: unknown[]) => Promise<unknown>;

      const wrappedHandler = async (...allArgs: unknown[]) => {
        // Extract extra from the correct position (defensive: handle arg-less tool pattern)
        let extra: EnrichedExtra;
        if (allArgs.length <= extraPosition) {
          // Arg-less tool pattern: keep args as-is, create separate extra object
          extra = (allArgs[0] && typeof allArgs[0] === 'object' ? {} : {}) as EnrichedExtra;
          allArgs[extraPosition] = extra;
        } else {
          extra = (allArgs[extraPosition] || {}) as EnrichedExtra;
          allArgs[extraPosition] = extra;
        }

        // Helper: retry once after open+poll completes
        const ensureAuthenticatedOrThrow = async (): Promise<string> => {
          try {
            // Check for backchannel override via _meta.accountId
            let accountId: string | undefined;
            try {
              accountId = extra._meta?.accountId ?? (await getActiveAccount(tokenStore, { service }));
            } catch (error) {
              if (error instanceof Error && (((error as { code?: string }).code === 'REQUIRES_AUTHENTICATION' || error.name === 'AccountManagerError') as boolean)) {
                accountId = undefined;
              } else {
                throw error;
              }
            }

            // Eagerly validate token exists or trigger OAuth flow
            await this.getAccessToken(accountId);

            // After OAuth flow completes, get the actual accountId (email) that was set
            const effectiveAccountId = accountId ?? (await getActiveAccount(tokenStore, { service }));
            if (!effectiveAccountId) {
              throw new Error(`No account found after OAuth flow for service ${service}`);
            }

            return effectiveAccountId;
          } catch (error) {
            if (error instanceof AuthRequiredError && error.descriptor.kind === 'auth_url') {
              // Headless: don't open/poll; just propagate to outer handler to return auth_required.
              if (this.config.headless) throw error;

              // Non-headless: open once + poll until callback completes, then retry token acquisition.
              const authUrl = new URL(error.descriptor.url);
              const state = authUrl.searchParams.get('state');
              if (!state) throw new Error('Auth URL missing state parameter');

              if (!this.openedStates.has(state)) {
                this.openedStates.add(state);
                open(error.descriptor.url).catch((e: unknown) => {
                  logger.info('Failed to open browser automatically', { error: e instanceof Error ? e.message : String(e) });
                });
              }

              // Block until callback completes (or timeout)
              await this.waitForOAuthCompletion(state);

              // Cleanup pending state after we observe completion
              await this.deletePendingAuth(state);

              // Retry after completion
              return await ensureAuthenticatedOrThrow();
            }

            throw error;
          }
        };

        try {
          const effectiveAccountId = await ensureAuthenticatedOrThrow();
          const auth = this.toAuthProvider(effectiveAccountId);

          // Inject authContext and logger into extra
          (extra as { authContext?: AuthContext }).authContext = {
            auth,
            accountId: effectiveAccountId,
          };
          (extra as { logger?: unknown }).logger = logger;

          // Call original handler with all args
          return await originalHandler(...allArgs);
        } catch (error) {
          // Token retrieval/refresh failed - return auth required
          if (error instanceof AuthRequiredError) {
            logger.info('Authentication required', {
              service,
              tool: operation,
              descriptor: error.descriptor,
            });

            // Return auth_required response wrapped in { result } to match tool outputSchema pattern
            // Tools define outputSchema: z.object({ result: discriminatedUnion(...) }) where auth_required is a branch
            const authRequiredResponse = {
              type: 'auth_required' as const,
              provider: service,
              message: `Authentication required for ${operation}. Please authenticate with ${service}.`,
              url: error.descriptor.kind === 'auth_url' ? error.descriptor.url : undefined,
            };

            return {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({ result: authRequiredResponse }),
                },
              ],
              structuredContent: { result: authRequiredResponse },
            };
          }

          // Other errors - propagate
          throw error;
        }
      };

      return {
        ...module,
        handler: wrappedHandler,
      } as T;
    };

    return {
      // Use structural constraints to avoid contravariance check on handler type.
      // wrapAtPosition is now generic and returns T directly.
      withToolAuth: <T extends { name: string; config: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 1),
      withResourceAuth: <T extends { name: string; template?: unknown; config?: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 2),
      withPromptAuth: <T extends { name: string; config: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 0),
    };
  }
}

/**
 * Create a loopback OAuth client for Microsoft services
 * Works for both stdio and HTTP transports
 */
export function createMicrosoftFileAuth(config: LoopbackOAuthConfig): OAuth2TokenStorageProvider {
  return new LoopbackOAuthProvider(config);
}
