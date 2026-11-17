/**
 * Failure of a refresh-token grant against the upstream provider.
 *
 * The provider's token endpoint answers a rejected refresh with an RFC 6749 §5.2
 * error body, e.g. HTTP 400 `{"error":"invalid_grant","error_description":"AADSTS70000: The refresh token has expired or been revoked."}`.
 * `oauthError` carries that `error` code so callers can tell a revoked or expired
 * refresh token (the user must sign in again) from a transport or provider outage.
 */
export class ProviderRefreshError extends Error {
  readonly status: number;
  readonly oauthError?: string;

  constructor(status: number, body: string) {
    super(`Token refresh failed: ${status} ${body}`);
    this.name = 'ProviderRefreshError';
    this.status = status;
    this.oauthError = parseOAuthError(body);
  }
}

function parseOAuthError(body: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === 'object' && 'error' in parsed && typeof parsed.error === 'string') return parsed.error;
  } catch {
    // Not a JSON error body: no OAuth error code to report.
  }
  return undefined;
}

/** True when the provider rejected the refresh token itself (`invalid_grant`), so only a new sign-in recovers. */
export function isRevokedRefreshToken(error: unknown): boolean {
  return error instanceof ProviderRefreshError && error.oauthError === 'invalid_grant';
}
