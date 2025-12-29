/**
 * DCR Provider - Stateless Dynamic Client Registration Provider
 *
 * Implements stateless provider pattern where provider tokens are received from
 * token verification context rather than managed by the provider itself.
 *
 * Use case: MCP HTTP servers with DCR authentication where client manages tokens
 * and provider only handles Microsoft Graph API calls with provided credentials.
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { fetchWithTimeout } from '../lib/fetch-with-timeout.ts';
import type { AuthContext, EnrichedExtra, Logger, MicrosoftAuthProvider } from '../types.ts';

/**
 * DCR Provider configuration
 */
export interface DcrOAuthProviderConfig {
  /** Microsoft application client ID */
  clientId: string;

  /** Microsoft application client secret (optional for public clients) */
  clientSecret?: string;

  /** Azure AD tenant ID */
  tenantId: string;

  /** OAuth scopes */
  scope: string;

  /** Custom token endpoint URL (for testing, defaults to Microsoft OAuth endpoint) */
  tokenUrl?: string;

  /** DCR token verification endpoint URL (e.g., http://localhost:3000/oauth/verify) */
  verifyEndpoint: string;

  /** Logger for auth operations */
  logger: Logger;
}

/**
 * Microsoft Graph TokenResponse
 */
interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

/**
 * DCR Provider - Stateless OAuth provider for Dynamic Client Registration
 *
 * Unlike LoopbackOAuthProvider which manages token storage, DcrOAuthProvider is stateless:
 * - Receives provider tokens from verification context (HTTP bearer auth)
 * - Creates auth providers on-demand from tokens
 * - Handles token refresh using Microsoft OAuth
 * - No token storage dependency
 *
 * Pattern:
 * ```typescript
 * const provider = new DcrOAuthProvider(config);
 * const auth = provider.toAuthProvider(providerTokens);
 * const accessToken = await auth.getAccessToken();
 * ```
 */
export class DcrOAuthProvider {
  private config: DcrOAuthProviderConfig;
  private emailCache = new Map<string, { email: string; expiresAt: number }>();

  constructor(config: DcrOAuthProviderConfig) {
    this.config = config;
  }

  /**
   * Create Microsoft Graph auth provider from provider tokens
   *
   * This is the core stateless pattern - provider receives tokens from context
   * (token verification, HTTP request) and creates auth provider on-demand.
   *
   * @param tokens - Provider tokens (Microsoft access/refresh tokens)
   * @returns Microsoft Graph-compatible auth provider
   */
  toAuthProvider(tokens: ProviderTokens): MicrosoftAuthProvider {
    // Capture tokens in closure for auth provider
    let currentTokens = { ...tokens };

    return {
      getAccessToken: async (): Promise<string> => {
        // Check if token is still valid
        if (this.isTokenValid(currentTokens)) {
          return currentTokens.accessToken;
        }

        // Token expired - try refresh if available
        if (currentTokens.refreshToken) {
          try {
            const refreshedTokens = await this.refreshAccessToken(currentTokens.refreshToken);
            currentTokens = refreshedTokens;
            return currentTokens.accessToken;
          } catch (error) {
            throw new Error(`Token refresh failed: ${error instanceof Error ? error.message : String(error)}`);
          }
        }

        // No refresh token - token expired and cannot refresh
        throw new Error('Access token expired and no refresh token available');
      },
    };
  }

  /**
   * Check if token is still valid (with 1 minute buffer)
   */
  private isTokenValid(tokens: ProviderTokens): boolean {
    if (!tokens.expiresAt) return true; // No expiry = assume valid
    return Date.now() < tokens.expiresAt - 60000; // 1 minute buffer
  }

  /**
   * Refresh Microsoft access token using refresh token
   *
   * @param refreshToken - Microsoft refresh token
   * @returns New provider tokens
   */
  async refreshAccessToken(refreshToken: string): Promise<ProviderTokens> {
    const { clientId, clientSecret, tenantId, scope, tokenUrl: customTokenUrl } = this.config;

    const tokenUrl = customTokenUrl ?? `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
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
   * Get user email from Microsoft Graph API (with caching)
   *
   * @param tokens - Provider tokens to use for API call
   * @returns User's email address
   */
  async getUserEmail(tokens: ProviderTokens): Promise<string> {
    const cacheKey = tokens.accessToken;
    const cached = this.emailCache.get(cacheKey);

    // Check cache (with same expiry as access token)
    if (cached && Date.now() < cached.expiresAt) {
      return cached.email;
    }

    const auth = this.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    const response = await fetchWithTimeout('https://graph.microsoft.com/v1.0/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.status} ${await response.text()}`);
    }

    const userInfo = (await response.json()) as { mail?: string; userPrincipalName: string };
    const email = userInfo.mail ?? userInfo.userPrincipalName;

    // Cache with token expiration (default 1 hour if not specified)
    this.emailCache.set(cacheKey, {
      email,
      expiresAt: tokens.expiresAt ?? Date.now() + 3600000,
    });

    return email;
  }

  /**
   * Auth middleware for HTTP servers with DCR bearer auth
   * Validates bearer tokens and enriches extra with provider tokens
   *
   * Pattern:
   * ```typescript
   * const provider = new DcrOAuthProvider({ ..., verifyEndpoint: 'http://localhost:3000/oauth/verify' });
   * const middleware = provider.authMiddleware();
   * const tools = toolFactories.map(f => f()).map(middleware.withToolAuth);
   * const resources = resourceFactories.map(f => f()).map(middleware.withResourceAuth);
   * const prompts = promptFactories.map(f => f()).map(middleware.withPromptAuth);
   * ```
   */
  authMiddleware() {
    // Shared wrapper logic - extracts extra parameter from specified position
    // Generic T captures the actual module type; handler is cast from unknown to callable
    const wrapAtPosition = <T extends { name: string; handler: unknown; [key: string]: unknown }>(module: T, extraPosition: number): T => {
      const originalHandler = module.handler as (...args: unknown[]) => Promise<unknown>;

      const wrappedHandler = async (...allArgs: unknown[]) => {
        // Extract extra from the correct position
        const extra = allArgs[extraPosition] as EnrichedExtra;

        // Extract DCR bearer token from SDK's authInfo (if present) or request headers
        let bearerToken: string | undefined;

        // Option 1: Token already verified by SDK's bearerAuth middleware
        if (extra.authInfo && typeof extra.authInfo === 'object') {
          // authInfo contains the validated token - extract it
          // The SDK's bearerAuth middleware already validated it, but we need the raw token for /oauth/verify
          // Check if authInfo has the token directly, otherwise extract from headers
          const authInfo = extra.authInfo as unknown as Record<string, unknown>;
          bearerToken = (typeof authInfo.accessToken === 'string' ? authInfo.accessToken : undefined) ?? (typeof authInfo.token === 'string' ? authInfo.token : undefined);
        }

        // Option 2: Extract from Authorization header
        if (!bearerToken && extra.requestInfo?.headers) {
          const authHeader = extra.requestInfo.headers.authorization || extra.requestInfo.headers.Authorization;
          if (authHeader) {
            // Handle both string and string[] types
            const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
            if (headerValue) {
              const match = /^Bearer\s+(.+)$/i.exec(headerValue);
              if (match) {
                bearerToken = match[1];
              }
            }
          }
        }

        if (!bearerToken) {
          throw new McpError(ErrorCode.InvalidRequest, 'Missing Authorization header. DCR mode requires bearer token.');
        }

        // Call /oauth/verify to validate DCR token and get provider tokens
        const verifyResponse = await fetchWithTimeout(this.config.verifyEndpoint, {
          headers: { Authorization: `Bearer ${bearerToken}` },
        });

        if (!verifyResponse.ok) {
          throw new McpError(ErrorCode.InvalidRequest, `Token verification failed: ${verifyResponse.status}`);
        }

        const verifyData = (await verifyResponse.json()) as {
          providerTokens: ProviderTokens;
        };

        // Fetch user email to use as accountId (with caching)
        let accountId: string;
        try {
          accountId = await this.getUserEmail(verifyData.providerTokens);
        } catch (error) {
          throw new McpError(ErrorCode.InternalError, `Failed to get user email for DCR authentication: ${error instanceof Error ? error.message : String(error)}`);
        }

        // Create auth provider from provider tokens
        const auth = this.toAuthProvider(verifyData.providerTokens);

        // Inject authContext and logger into extra
        (extra as { authContext?: AuthContext }).authContext = {
          auth,
          accountId, // User's email address
        };
        (extra as { logger?: unknown }).logger = this.config.logger;

        // Call original handler with all args
        return await originalHandler(...allArgs);
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
