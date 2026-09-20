import type { CachedToken } from '../types.ts';

export interface RefreshTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

export function createRefreshedToken(response: RefreshTokenResponse, previousRefreshToken: string): CachedToken {
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token || previousRefreshToken,
    ...(response.expires_in !== undefined && { expiresAt: Date.now() + response.expires_in * 1000 }),
    ...(response.scope !== undefined && { scope: response.scope }),
  };
}
