/**
 * DCR Token Verification Utilities
 *
 * Provides token verification for both self-hosted and external DCR modes:
 * - Self-hosted: Verifies tokens against local DCR router (/oauth/verify)
 * - External: Verifies tokens against Auth0/Stitch verification endpoint
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import { fetchWithTimeout } from './fetch-with-timeout.ts';

/**
 * Verification result from DCR authorization server
 */
export interface VerificationResult {
  /** Bearer token that was verified */
  token: string;
  /** Client ID associated with the token */
  clientId: string;
  /** OAuth scopes granted to the token */
  scopes: string[];
  /** Token expiration timestamp (milliseconds since epoch) */
  expiresAt: number;
  /** Provider tokens (Microsoft access/refresh tokens) */
  providerTokens: ProviderTokens;
}

/**
 * Verify bearer token against DCR authorization server
 *
 * Supports both self-hosted and external DCR modes by calling the
 * /oauth/verify endpoint (or equivalent external URL).
 *
 * @param bearerToken - Bearer token to verify (without "Bearer " prefix)
 * @param verifyUrl - Verification endpoint URL (self-hosted or external)
 * @returns Verification result with provider tokens
 * @throws Error if verification fails
 *
 * @example Self-hosted mode
 * ```typescript
 * const result = await verifyBearerToken(
 *   token,
 *   'http://localhost:3456/oauth/verify'
 * );
 * const auth = provider.toAuthProvider(result.providerTokens);
 * ```
 *
 * @example External mode (Auth0/Stitch)
 * ```typescript
 * const result = await verifyBearerToken(
 *   token,
 *   'https://auth.example.com/oauth/verify'
 * );
 * const auth = provider.toAuthProvider(result.providerTokens);
 * ```
 */
export async function verifyBearerToken(bearerToken: string, verifyUrl: string): Promise<VerificationResult> {
  const response = await fetchWithTimeout(verifyUrl, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${bearerToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token verification failed: ${response.status} ${errorText}`);
  }

  const result = (await response.json()) as VerificationResult;

  // Validate required fields
  if (!result.providerTokens || !result.providerTokens.accessToken) {
    throw new Error('Verification response missing required provider tokens');
  }

  return result;
}
