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
 */

import { addAccount, generatePKCE, getActiveAccount, getErrorTemplate, getSuccessTemplate, getToken, listAccountIds, type OAuth2TokenStorageProvider, setAccountInfo, setActiveAccount, setToken } from '@mcp-z/oauth';
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

    // No valid token or no account - check if we can start OAuth flow
    const { headless } = this.config;
    if (headless) {
      // In headless mode (production), cannot start OAuth flow
      // Throw AuthRequiredError with auth_url descriptor for MCP tool response
      const { clientId, tenantId, scope } = this.config;

      // Incremental OAuth detection: Check if other accounts exist
      const existingAccounts = await this.getExistingAccounts();
      const hasOtherAccounts = effectiveAccountId ? existingAccounts.length > 0 && !existingAccounts.includes(effectiveAccountId) : existingAccounts.length > 0;

      // Build informational OAuth URL for headless mode
      // Note: No redirect_uri included - user must use account-add tool which starts proper ephemeral server
      const authUrl = new URL(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`);
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', scope);
      authUrl.searchParams.set('response_mode', 'query');
      authUrl.searchParams.set('prompt', 'select_account');

      // Provide context-aware hint based on existing accounts
      let hint: string;
      if (hasOtherAccounts) {
        hint = `Existing ${service} accounts found. Use account-list to view, account-switch to change account, or account-add to add new account`;
      } else if (effectiveAccountId) {
        hint = `Use account-add to authenticate ${effectiveAccountId}`;
      } else {
        hint = 'Use account-add to authenticate interactively';
      }

      const baseDescriptor = {
        kind: 'auth_url' as const,
        provider: 'microsoft',
        url: authUrl.toString(),
        hint,
      };

      const descriptor: AuthFlowDescriptor & { accountId?: string } = effectiveAccountId ? { ...baseDescriptor, accountId: effectiveAccountId } : baseDescriptor;

      throw new AuthRequiredError(descriptor);
    }

    // Interactive mode - start ephemeral OAuth flow
    logger.info('Starting ephemeral OAuth flow', { service, headless });
    const { token, email } = await this.performEphemeralOAuthFlow();

    // Store token with email as accountId
    await setToken(tokenStore, { accountId: email, service }, token);

    // Register account in account management system
    await addAccount(tokenStore, { service, accountId: email });

    // Set as active account so subsequent getAccessToken() calls find it
    await setActiveAccount(tokenStore, { service, accountId: email });

    // Store account metadata (email, added timestamp)
    await setAccountInfo(
      tokenStore,
      { service, accountId: email },
      {
        email,
        addedAt: new Date().toISOString(),
      }
    );

    logger.info('OAuth flow completed', { service, accountId: email });

    return token.accessToken;
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
   * Authenticate new account with OAuth flow
   * Triggers account selection, stores token, registers account
   *
   * @returns Email address of newly authenticated account
   * @throws Error in headless mode (cannot open browser for OAuth)
   */
  async authenticateNewAccount(): Promise<string> {
    const { logger, headless, service, tokenStore } = this.config;

    if (headless) {
      throw new Error('Cannot authenticate new account in headless mode - interactive OAuth required');
    }

    logger.info('Starting new account authentication', { service });

    // Trigger OAuth with account selection
    const { token, email } = await this.performEphemeralOAuthFlow();

    // Store token
    await setToken(tokenStore, { accountId: email, service }, token);

    // Register account
    await addAccount(tokenStore, { service, accountId: email });

    // Set as active account
    await setActiveAccount(tokenStore, { service, accountId: email });

    // Store account metadata
    await setAccountInfo(
      tokenStore,
      { service, accountId: email },
      {
        email,
        addedAt: new Date().toISOString(),
      }
    );

    logger.info('New account authenticated', { service, email });
    return email;
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

  /**
   * Check for existing accounts in token storage (incremental OAuth detection)
   *
   * Uses key-utils helper for forward compatibility with key format changes.
   *
   * @returns Array of account IDs that have tokens for this service
   */
  private async getExistingAccounts(): Promise<string[]> {
    const { service, tokenStore } = this.config;
    return listAccountIds(tokenStore, service);
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

  private async performEphemeralOAuthFlow(): Promise<{ token: CachedToken; email: string }> {
    const { clientId, tenantId, scope, headless, logger, redirectUri: configRedirectUri } = this.config;

    // Parse redirectUri if provided to extract host, protocol, port, and path
    let targetHost = 'localhost'; // Default: localhost (Microsoft requires exact match with registered redirect URI)
    let targetPort = 0; // Default: OS-assigned ephemeral port
    let targetProtocol = 'http:'; // Default: http
    let callbackPath = '/callback'; // Default callback path
    let useConfiguredUri = false;

    if (configRedirectUri) {
      try {
        const parsed = new URL(configRedirectUri);

        // Use configured redirect URI as-is for production deployments
        targetHost = parsed.hostname;
        targetProtocol = parsed.protocol;

        // Extract port from URL (use default ports if not specified)
        if (parsed.port) {
          targetPort = Number.parseInt(parsed.port, 10);
        } else {
          targetPort = parsed.protocol === 'https:' ? 443 : 80;
        }

        // Extract path (default to /callback if URL has no path or just '/')
        if (parsed.pathname && parsed.pathname !== '/') {
          callbackPath = parsed.pathname;
        }

        useConfiguredUri = true;

        logger.debug('Using configured redirect URI', {
          host: targetHost,
          protocol: targetProtocol,
          port: targetPort,
          path: callbackPath,
          redirectUri: configRedirectUri,
        });
      } catch (error) {
        logger.warn('Failed to parse redirectUri, using ephemeral defaults', {
          redirectUri: configRedirectUri,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue with defaults (127.0.0.1, port 0, http, /callback)
      }
    }

    return new Promise((resolve, reject) => {
      // Generate PKCE challenge
      const { verifier: codeVerifier, challenge: codeChallenge } = generatePKCE();

      let server: http.Server | null = null;
      let serverPort: number;
      let finalRedirectUri: string; // Will be set in server.listen callback

      // Create ephemeral server with OS-assigned port (RFC 8252)
      server = http.createServer(async (req, res) => {
        if (!req.url) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(getErrorTemplate('Invalid request'));
          server?.close();
          reject(new Error('Invalid request: missing URL'));
          return;
        }
        const url = new URL(req.url, `http://localhost:${serverPort}`);

        if (url.pathname === callbackPath) {
          const code = url.searchParams.get('code');
          const error = url.searchParams.get('error');

          if (error) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(getErrorTemplate(error));
            server?.close();
            reject(new Error(`OAuth error: ${error}`));
            return;
          }

          if (!code) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(getErrorTemplate('No authorization code received'));
            server?.close();
            reject(new Error('No authorization code received'));
            return;
          }

          try {
            // Exchange code for token (must use same redirect_uri as in authorization request)
            const tokenResponse = await this.exchangeCodeForToken(code, codeVerifier, finalRedirectUri);

            // Build cached token
            const cachedToken: CachedToken = {
              accessToken: tokenResponse.access_token,
              ...(tokenResponse.refresh_token !== undefined && { refreshToken: tokenResponse.refresh_token }),
              ...(tokenResponse.expires_in !== undefined && { expiresAt: Date.now() + tokenResponse.expires_in * 1000 }),
              ...(tokenResponse.scope !== undefined && { scope: tokenResponse.scope }),
            };

            // Fetch user email immediately using the new access token
            const email = await this.fetchUserEmailFromToken(tokenResponse.access_token);

            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(getSuccessTemplate());
            server?.close();
            resolve({ token: cachedToken, email });
          } catch (exchangeError) {
            logger.error('Token exchange failed', { error: exchangeError instanceof Error ? exchangeError.message : String(exchangeError) });
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end(getErrorTemplate('Token exchange failed'));
            server?.close();
            reject(exchangeError);
          }
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      // Listen on targetPort (0 for OS assignment, or custom port from redirectUri)
      server.listen(targetPort, targetHost, () => {
        const address = server?.address();
        if (!address || typeof address === 'string') {
          server?.close();
          reject(new Error('Failed to start ephemeral server'));
          return;
        }

        serverPort = address.port;

        // Construct final redirect URI
        if (useConfiguredUri && configRedirectUri) {
          // Use configured redirect URI as-is for production
          finalRedirectUri = configRedirectUri;
        } else {
          // Construct ephemeral redirect URI with actual server port
          finalRedirectUri = `${targetProtocol}//${targetHost}:${serverPort}${callbackPath}`;
        }

        // Build Microsoft auth URL
        const authUrl = new URL(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`);
        authUrl.searchParams.set('client_id', clientId);
        authUrl.searchParams.set('redirect_uri', finalRedirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', scope);
        authUrl.searchParams.set('response_mode', 'query');
        authUrl.searchParams.set('code_challenge', codeChallenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');
        authUrl.searchParams.set('prompt', 'select_account');

        logger.info('Ephemeral OAuth server started', { port: serverPort, headless });

        if (headless) {
          // Headless mode: Print auth URL to stderr (stdout is MCP protocol)
          console.error('\n🔐 OAuth Authorization Required');
          console.error('📋 Please visit this URL in your browser:\n');
          console.error(`   ${authUrl.toString()}\n`);
          console.error('⏳ Waiting for authorization...\n');
        } else {
          // Interactive mode: Open browser automatically
          logger.info('Opening browser for OAuth authorization');
          open(authUrl.toString()).catch((error) => {
            logger.info('Failed to open browser automatically', { error: error.message });
            console.error('\n🔐 OAuth Authorization Required');
            console.error(`   ${authUrl.toString()}\n`);
          });
        }
      });

      // Timeout after 5 minutes
      setTimeout(
        () => {
          if (server) {
            server.close();
            reject(new Error('OAuth flow timed out after 5 minutes'));
          }
        },
        5 * 60 * 1000
      );
    });
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
    const { clientId, clientSecret, tenantId, scope } = this.config;

    const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const params: Record<string, string> = {
      refresh_token: refreshToken,
      client_id: clientId,
      grant_type: 'refresh_token',
      scope,
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

        try {
          // Check for backchannel override via _meta.accountId
          let accountId: string | undefined;
          try {
            accountId = extra._meta?.accountId ?? (await getActiveAccount(tokenStore, { service }));
          } catch (error) {
            if (error instanceof Error && ((error as { code?: string }).code === 'REQUIRES_AUTHENTICATION' || error.name === 'AccountManagerError')) {
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
