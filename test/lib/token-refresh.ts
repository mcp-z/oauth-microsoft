/**
 * Token Refresh Utilities for Integration Tests
 *
 * Provides automatic token refresh for MCP OAuth integration tests.
 * Prevents test failures due to expired tokens by checking expiry and
 * refreshing when needed.
 *
 * Design:
 * - Checks token expiry before returning (< 5 min threshold)
 * - Auto-refreshes using Microsoft OAuth API
 * - FAILS FAST with clear error if refresh fails (no silent fallback)
 * - Updates token store with refreshed tokens
 */

import { createAccountKey } from '@mcp-z/oauth';
import type Keyv from 'keyv';

/**
 * Cached token format matching LoopbackOAuthProvider
 */
export interface CachedToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  scope?: string;
}

/**
 * Token response from Microsoft OAuth API
 */
interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

/**
 * Refresh Microsoft OAuth access token
 *
 * Calls Microsoft's token endpoint to exchange refresh token for new access token.
 * This mimics the refresh logic from LoopbackOAuthProvider.
 *
 * @param refreshToken - Valid Microsoft refresh token
 * @param clientId - Microsoft OAuth client ID
 * @param tenantId - Microsoft tenant ID (usually 'common' for multi-tenant apps)
 * @param scope - OAuth scopes (space-separated, e.g., "User.Read Mail.Read")
 * @param clientSecret - Microsoft OAuth client secret (optional for public clients)
 * @returns Refreshed token with new access token and expiry
 * @throws Error if refresh fails (revoked token, invalid credentials, network error)
 *
 * Common failure reasons:
 * - Refresh token expired (inactive for 90+ days)
 * - User revoked app access
 * - Client credentials changed
 * - Network connectivity issues
 * - Microsoft OAuth API issues
 */
export async function refreshMicrosoftToken(refreshToken: string, clientId: string, tenantId: string, scope: string, clientSecret?: string): Promise<CachedToken> {
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

  const response = await fetch(tokenUrl, {
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
    refreshToken: refreshToken, // Keep original refresh token (Microsoft may not return new one)
    ...(tokenResponse.expires_in !== undefined && { expiresAt: Date.now() + tokenResponse.expires_in * 1000 }),
    ...(tokenResponse.scope !== undefined && { scope: tokenResponse.scope }),
  };
}

/**
 * Get access token with automatic refresh if expired
 *
 * Checks if token is expired or expires soon (< 5 minutes) and automatically
 * refreshes it using Microsoft OAuth API. Updates token store with refreshed token.
 *
 * FAIL FAST Philosophy:
 * - If token not found: throw error with setup instructions
 * - If refresh fails: throw error with actionable guidance (NO silent fallback)
 * - If no refresh token: throw error (can't refresh)
 *
 * @param tokenStore - Keyv token store
 * @param accountId - Account identifier (email or 'default')
 * @param service - Service name (outlook, drive, etc.)
 * @param clientId - Microsoft OAuth client ID
 * @param tenantId - Microsoft tenant ID
 * @param scope - OAuth scopes (space-separated)
 * @param clientSecret - Microsoft OAuth client secret (optional)
 * @returns Fresh access token (refreshed if needed)
 * @throws Error if token not found, refresh fails, or no refresh token available
 *
 * @example
 * ```typescript
 * const tokenStore = new Keyv({ store: new KeyvFile({ filename: '.tokens/test/store.json' }) });
 * const token = await getRefreshedToken(tokenStore, 'test@example.com', 'outlook', CLIENT_ID, TENANT_ID, 'User.Read Mail.Read');
 * // Returns fresh token, automatically refreshed if expired
 * ```
 */
export async function getRefreshedToken(tokenStore: Keyv, accountId: string, service: string, clientId: string, tenantId: string, scope: string, clientSecret?: string): Promise<string> {
  const key = createAccountKey('token', { accountId: accountId, service: service });

  // KeyvFile wraps values in {value: ...} structure
  const tokenData = await tokenStore.get(key);
  const storedToken = tokenData?.value || tokenData;

  if (!storedToken?.accessToken) {
    throw new Error(`Token not found for ${accountId}:${service}.\n\nRun \`npm run test:setup\` in libs/oauth-microsoft/ to generate OAuth token.`);
  }

  // Check if token is expired or expires soon (< 5 min)
  // 5-minute threshold prevents race conditions during test execution
  const expiresAt = storedToken.expiresAt;
  const expirationThreshold = Date.now() + 5 * 60 * 1000; // 5 minutes
  const isExpiringSoon = expiresAt && expiresAt < expirationThreshold;

  if (isExpiringSoon && storedToken.refreshToken) {
    try {
      // Refresh token using Microsoft OAuth API
      const refreshedToken = await refreshMicrosoftToken(storedToken.refreshToken, clientId, tenantId, scope, clientSecret);

      // Update store with refreshed token
      await tokenStore.set(key, refreshedToken);

      return refreshedToken.accessToken;
    } catch (error) {
      // FAIL FAST - no graceful fallback
      // Tests should fail loudly when configuration is broken
      throw new Error(
        `Token refresh failed: ${error instanceof Error ? error.message : String(error)}\n\n` +
          'This usually means:\n' +
          '  1. Refresh token expired (inactive for 90+ days)\n' +
          '  2. App access was revoked by user\n' +
          '  3. Client credentials changed in .env.test\n' +
          '  4. Network connectivity issues\n\n' +
          'To fix: Run `npm run test:setup` in libs/oauth-microsoft/ to generate a new token.'
      );
    }
  }

  // Token expires soon but no refresh token available
  if (isExpiringSoon && !storedToken.refreshToken) {
    throw new Error('Token expires soon (< 5 minutes) but no refresh token available.\n\n' + 'Run `npm run test:setup` in libs/oauth-microsoft/ to generate a new token with refresh capability.');
  }

  return storedToken.accessToken;
}
