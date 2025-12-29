/**
 * DCR Token Verifier
 *
 * Validates bearer tokens by calling Authorization Server's verification endpoint.
 * Implements proper AS/RS separation - Resource Server doesn't access token storage.
 */

import type { ProviderTokens } from '@mcp-z/oauth';

/**
 * Authentication information from token verification
 */
export interface AuthInfo {
  /** Bearer access token */
  token: string;

  /** Client ID that owns the token */
  clientId: string;

  /** Granted scopes */
  scopes: string[];

  /** Token expiration timestamp (milliseconds since epoch) */
  expiresAt: number;

  /** Microsoft provider tokens (if available) */
  providerTokens?: ProviderTokens;
}

/**
 * DCR Token Verifier validates access tokens via Authorization Server
 *
 * This implements proper OAuth 2.0 architecture where the Resource Server
 * (MCP server) validates tokens by calling the Authorization Server's
 * verification endpoint rather than accessing token storage directly.
 */
export class DcrTokenVerifier {
  private verifyUrl: string;

  /**
   * @param verifyUrl - Authorization Server's /oauth/verify endpoint URL
   */
  constructor(verifyUrl: string) {
    this.verifyUrl = verifyUrl;
  }

  /**
   * Verify an access token by calling the Authorization Server
   *
   * @param token - Bearer access token to validate
   * @returns AuthInfo with token metadata and provider tokens
   * @throws Error if token is invalid or verification fails
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const response = await fetch(this.verifyUrl, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        let errorMessage = 'Unknown error';
        try {
          const error = await response.json();
          errorMessage = (error as { error_description?: string; error?: string }).error_description ?? (error as { error?: string }).error ?? errorMessage;
        } catch {
          // Failed to parse error JSON, use status text
          errorMessage = response.statusText;
        }
        throw new Error(`Token verification failed: ${errorMessage}`);
      }

      const authInfo = (await response.json()) as AuthInfo;
      return authInfo;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Token verification failed: ${String(error)}`);
    }
  }
}
