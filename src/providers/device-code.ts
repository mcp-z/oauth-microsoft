/**
 * Device Code OAuth Implementation for Microsoft
 *
 * Implements OAuth 2.0 Device Authorization Grant (RFC 8628) for headless/limited-input devices.
 * Designed for scenarios where interactive browser flows are impractical (SSH sessions, CI/CD, etc.).
 *
 * Flow:
 * 1. Request device code from Microsoft endpoint
 * 2. Display user_code and verification_uri to user
 * 3. Poll token endpoint until user completes authentication
 * 4. Cache access token + refresh token to storage
 * 5. Refresh tokens when expired
 *
 * Similar to service accounts in usage pattern: single static identity, minimal account management.
 */

import { getToken, type OAuth2TokenStorageProvider, setToken } from '@mcp-z/oauth';
import type { Keyv } from 'keyv';
import open from 'open';
import { fetchWithTimeout } from '../lib/fetch-with-timeout.ts';
import type { AuthContext, CachedToken, EnrichedExtra, Logger, MicrosoftAuthProvider, MicrosoftService } from '../types.ts';

/**
 * Device Code Flow Response
 * Response from Microsoft device authorization endpoint
 */
interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
  message?: string;
}

/**
 * Token Response from Microsoft OAuth endpoint
 */
interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  scope?: string;
  token_type?: string;
}

/**
 * Device Code Provider Configuration
 */
export interface DeviceCodeConfig {
  /** Microsoft service type (e.g., 'outlook') */
  service: MicrosoftService;
  /** Azure AD client ID */
  clientId: string;
  /** Azure AD tenant ID */
  tenantId: string;
  /** OAuth scopes to request (space-separated string or array) */
  scope: string;
  /** Logger instance */
  logger: Logger;
  /** Token storage for caching */
  tokenStore: Keyv<unknown>;
  /** Headless mode - print device code instead of opening browser */
  headless: boolean;
}

/**
 * DeviceCodeProvider implements OAuth2TokenStorageProvider using Microsoft Device Code Flow
 *
 * This provider:
 * - Initiates device code flow with Microsoft endpoint
 * - Displays user_code and verification_uri for manual authentication
 * - Polls token endpoint until user completes auth
 * - Stores access tokens + refresh tokens in Keyv storage
 * - Refreshes tokens when expired
 * - Provides single static identity (minimal account management like service accounts)
 *
 * @example
 * ```typescript
 * const provider = new DeviceCodeProvider({
 *   service: 'outlook',
 *   clientId: 'your-client-id',
 *   tenantId: 'common',
 *   scope: 'https://graph.microsoft.com/Mail.Read',
 *   logger: console,
 *   tokenStore: new Keyv(),
 *   headless: true,
 * });
 *
 * // Get authenticated Microsoft Graph client
 * const token = await provider.getAccessToken('default');
 * ```
 */
export class DeviceCodeProvider implements OAuth2TokenStorageProvider {
  private config: DeviceCodeConfig;

  constructor(config: DeviceCodeConfig) {
    this.config = config;
  }

  /**
   * Start device code flow and poll for token
   *
   * 1. POST to /devicecode endpoint to get device_code and user_code
   * 2. Display verification instructions to user
   * 3. Poll /token endpoint every interval seconds
   * 4. Handle authorization_pending, slow_down, expired_token errors
   * 5. Return token when user completes authentication
   */
  private async startDeviceCodeFlow(accountId: string): Promise<CachedToken> {
    const { clientId, tenantId, scope, logger, headless } = this.config;

    // Step 1: Request device code
    const deviceCodeEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/devicecode`;
    logger.debug('Requesting device code', { endpoint: deviceCodeEndpoint });

    const deviceCodeResponse = await fetchWithTimeout(deviceCodeEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        scope,
      }),
    });

    if (!deviceCodeResponse.ok) {
      const errorText = await deviceCodeResponse.text();
      throw new Error(`Device code request failed (HTTP ${deviceCodeResponse.status}): ${errorText}`);
    }

    const deviceCodeData = (await deviceCodeResponse.json()) as DeviceCodeResponse;
    const { device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval } = deviceCodeData;

    // Step 2: Display instructions to user
    logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    logger.info('Device code authentication required');
    logger.info('');
    logger.info(`Please visit: ${verification_uri_complete || verification_uri}`);
    logger.info(`And enter code: ${user_code}`);
    logger.info('');
    logger.info(`Code expires in ${expires_in} seconds`);
    logger.info('Waiting for authentication...');
    logger.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    // Optional: Open browser in non-headless mode
    if (!headless) {
      const urlToOpen = verification_uri_complete || verification_uri;
      try {
        await open(urlToOpen);
        logger.debug('Opened browser to verification URL', { url: urlToOpen });
      } catch (error) {
        logger.debug('Failed to open browser', { error: error instanceof Error ? error.message : String(error) });
      }
    }

    // Step 3: Poll token endpoint
    return await this.pollForToken(device_code, interval || 5, accountId);
  }

  /**
   * Poll Microsoft token endpoint until user completes authentication
   *
   * Handles Microsoft-specific error codes:
   * - authorization_pending: User hasn't completed auth yet, keep polling
   * - slow_down: Increase polling interval by 5 seconds
   * - authorization_declined: User denied authorization
   * - expired_token: Device code expired (typically after 15 minutes)
   */
  private async pollForToken(deviceCode: string, intervalSeconds: number, accountId: string): Promise<CachedToken> {
    const { clientId, tenantId, logger, service, tokenStore } = this.config;
    const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

    let currentInterval = intervalSeconds;
    const startTime = Date.now();

    while (true) {
      // Wait for polling interval
      await new Promise((resolve) => setTimeout(resolve, currentInterval * 1000));

      logger.debug('Polling for token', { elapsed: Math.floor((Date.now() - startTime) / 1000), interval: currentInterval });

      const response = await fetchWithTimeout(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: clientId,
          device_code: deviceCode,
        }),
      });

      const responseData = (await response.json()) as TokenResponse & { error?: string; error_description?: string };

      if (response.ok) {
        // Success! Convert to CachedToken and store
        const tokenData = responseData as TokenResponse;
        const token: CachedToken = {
          accessToken: tokenData.access_token,
          ...(tokenData.refresh_token && { refreshToken: tokenData.refresh_token }),
          expiresAt: Date.now() + (tokenData.expires_in - 60) * 1000, // 60s safety margin
          ...(tokenData.scope && { scope: tokenData.scope }),
        };

        // Cache token to storage
        await setToken(tokenStore, { accountId, service }, token);
        logger.info('Device code authentication successful', { accountId });

        return token;
      }

      // Handle error responses
      const error = responseData.error;
      const errorDescription = responseData.error_description || '';

      if (error === 'authorization_pending') {
        // User hasn't completed auth yet - continue polling
        logger.debug('Authorization pending, waiting for user...');
        continue;
      }

      if (error === 'slow_down') {
        // Microsoft wants us to slow down polling
        currentInterval += 5;
        logger.debug('Received slow_down, increasing interval', { newInterval: currentInterval });
        continue;
      }

      if (error === 'authorization_declined') {
        throw new Error('User declined authorization. Please restart the authentication flow.');
      }

      if (error === 'expired_token') {
        throw new Error('Device code expired. Please restart the authentication flow.');
      }

      // Unknown error
      throw new Error(`Device code flow failed: ${error} - ${errorDescription}`);
    }
  }

  /**
   * Refresh expired access token using refresh token
   *
   * @param refreshToken - Refresh token from previous authentication
   * @returns New cached token with fresh access token
   */
  private async refreshAccessToken(refreshToken: string): Promise<CachedToken> {
    const { clientId, tenantId, scope, logger } = this.config;
    const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

    logger.debug('Refreshing access token');

    const response = await fetchWithTimeout(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: refreshToken,
        scope,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed (HTTP ${response.status}): ${errorText}`);
    }

    const tokenData = (await response.json()) as TokenResponse;

    return {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || refreshToken, // Some responses may not include new refresh token
      expiresAt: Date.now() + (tokenData.expires_in - 60) * 1000, // 60s safety margin
      scope: tokenData.scope || scope,
    };
  }

  /**
   * Check if token is still valid (not expired)
   */
  private isTokenValid(token: CachedToken): boolean {
    return token.expiresAt !== undefined && token.expiresAt > Date.now();
  }

  /**
   * Get access token for Microsoft Graph API
   *
   * Flow:
   * 1. Check token storage
   * 2. If valid token exists, return it
   * 3. If expired but has refresh token, try refresh
   * 4. Otherwise, start new device code flow
   *
   * @param accountId - Account identifier. Defaults to 'device-code' (fixed identifier for device code flow).
   * @returns Access token for API requests
   */
  async getAccessToken(accountId?: string): Promise<string> {
    const { logger, service, tokenStore } = this.config;
    const effectiveAccountId = accountId ?? 'device-code';

    logger.debug('Getting access token', { service, accountId: effectiveAccountId });

    // Check storage for cached token
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
        logger.info('Token refresh failed', {
          accountId: effectiveAccountId,
          error: error instanceof Error ? error.message : String(error),
        });
        // In headless mode, cannot start interactive device code flow
        if (this.config.headless) {
          throw new Error(`Token refresh failed in headless mode. Cannot start interactive device code flow. Error: ${error instanceof Error ? error.message : String(error)}`);
        }
        // Fall through to new device code flow (interactive mode only)
      }
    }

    // No valid token - check if we can start device code flow
    if (this.config.headless) {
      throw new Error('No valid token available in headless mode. Device code flow requires user interaction. ' + 'Please run authentication flow interactively first or provide valid tokens.');
    }

    // Interactive mode - start device code flow
    logger.info('Starting device code flow', { accountId: effectiveAccountId });
    const token = await this.startDeviceCodeFlow(effectiveAccountId);
    return token.accessToken;
  }

  /**
   * Get user email from Microsoft Graph /me endpoint (pure query)
   *
   * @param accountId - Account identifier
   * @returns User's email address (userPrincipalName or mail field)
   */
  async getUserEmail(accountId?: string): Promise<string> {
    const { logger } = this.config;
    // Device code is single-account mode
    const token = await this.getAccessToken(accountId);

    logger.debug('Fetching user email from Microsoft Graph');

    const response = await fetchWithTimeout('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to get user email (HTTP ${response.status}): ${errorText}`);
    }

    const userData = (await response.json()) as { userPrincipalName?: string; mail?: string };
    const email = userData.userPrincipalName || userData.mail;

    if (!email) {
      throw new Error('User email not found in Microsoft Graph response');
    }

    return email;
  }

  /**
   * Create auth provider for Microsoft Graph SDK integration
   *
   * Device code provider ALWAYS uses fixed accountId='device-code'
   * This is by design - device code is a single static identity pattern
   *
   * @param accountId - Account identifier (must be 'device-code' or undefined, otherwise throws error)
   * @returns Auth provider with getAccessToken method
   */
  toAuthProvider(accountId?: string): { getAccessToken: () => Promise<string> } {
    // Device code ONLY works with 'device-code' account ID
    if (accountId !== undefined && accountId !== 'device-code') {
      throw new Error(`DeviceCodeProvider only supports accountId='device-code', got '${accountId}'. Device code uses a single static identity pattern.`);
    }

    // ALWAYS use fixed 'device-code' account ID
    const getToken = () => this.getAccessToken('device-code');

    return {
      getAccessToken: getToken,
    };
  }

  /**
   * Create Microsoft Graph AuthenticationProvider for SDK usage
   *
   * @param accountId - Account identifier
   * @returns AuthenticationProvider that provides access tokens
   */
  private createAuthProvider(accountId?: string): MicrosoftAuthProvider {
    return {
      getAccessToken: async () => {
        return await this.getAccessToken(accountId);
      },
    };
  }

  /**
   * Create middleware wrapper for single-user authentication
   *
   * Middleware wraps tool, resource, and prompt handlers and injects authContext into extra parameter.
   * Handlers receive MicrosoftAuthProvider via extra.authContext.auth for API calls.
   *
   * @returns Object with withToolAuth, withResourceAuth, withPromptAuth methods
   *
   * @example
   * ```typescript
   * // Server registration
   * const middleware = provider.authMiddleware();
   * const tools = toolFactories.map(f => f()).map(middleware.withToolAuth);
   * const resources = resourceFactories.map(f => f()).map(middleware.withResourceAuth);
   * const prompts = promptFactories.map(f => f()).map(middleware.withPromptAuth);
   *
   * // Tool handler receives auth
   * async function handler({ id }: In, extra: EnrichedExtra) {
   *   // extra.authContext.auth is MicrosoftAuthProvider (from middleware)
   *   const graph = Client.initWithMiddleware({ authProvider: extra.authContext.auth });
   * }
   * ```
   */
  authMiddleware() {
    // Shared wrapper logic - extracts extra parameter from specified position
    // Generic T captures the actual module type; handler is cast from unknown to callable
    const wrapAtPosition = <T extends { name: string; handler: unknown; [key: string]: unknown }>(module: T, extraPosition: number): T => {
      const originalHandler = module.handler as (...args: unknown[]) => Promise<unknown>;

      const wrappedHandler = async (...allArgs: unknown[]) => {
        // Extract extra from the correct position (defensive: handle arg-less tool pattern)
        // If called with fewer args than expected, use first arg as both args and extra
        let extra: EnrichedExtra;
        if (allArgs.length <= extraPosition) {
          // Arg-less tool pattern: single argument is both args and extra
          extra = (allArgs[0] || {}) as EnrichedExtra;
          allArgs[0] = extra;
          allArgs[extraPosition] = extra;
        } else {
          extra = (allArgs[extraPosition] || {}) as EnrichedExtra;
          allArgs[extraPosition] = extra;
        }

        try {
          // Use fixed accountId for storage isolation (like service-account pattern)
          const accountId = 'device-code';

          // Create Microsoft Graph authentication provider
          const auth = this.createAuthProvider(accountId);

          // Inject authContext and logger into extra parameter
          (extra as { authContext?: AuthContext }).authContext = {
            auth, // MicrosoftAuthProvider for Graph SDK
            accountId, // Account identifier
          };
          (extra as { logger?: unknown }).logger = this.config.logger;

          // Call original handler with all args
          return await originalHandler(...allArgs);
        } catch (error) {
          // Wrap auth errors with helpful context
          throw new Error(`Device code authentication failed: ${error instanceof Error ? error.message : String(error)}`);
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
