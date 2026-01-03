/**
 * DCR Token Helper Utilities
 *
 * Utilities for loading stored DCR tokens and injecting them into test environments.
 * Enables automated DCR testing without manual browser interaction.
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../src/lib/dcr-utils.ts';
import type { RegisteredClient } from '../../src/types.ts';

interface DcrTokenData {
  clientId: string;
  clientSecret: string;
  providerRefreshToken: string;
  providerAccessToken: string;
  providerExpiresAt: number;
}

/**
 * Load stored DCR tokens from .tokens/dcr.json
 *
 * @param provider - Provider name ('microsoft')
 * @returns DCR token data or undefined if not found
 */
export async function loadDcrTokens(): Promise<DcrTokenData | undefined> {
  const provider = 'microsoft';
  try {
    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({
      store: new KeyvFile({ filename: dcrTokenPath }),
    });

    const tokens = await dcrStore.get(provider);
    return tokens as DcrTokenData | undefined;
  } catch (_error) {
    // File doesn't exist or can't be read
    return undefined;
  }
}

/**
 * Pre-register a test DCR client in the store
 *
 * @param store - DCR server's Keyv store
 * @param clientId - Test client ID
 * @param clientSecret - Test client secret
 * @param redirectUri - Callback redirect URI
 */
export async function preRegisterTestClient(store: Keyv, clientId: string, clientSecret: string, redirectUri: string): Promise<void> {
  const client: RegisteredClient = {
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0, // Never expires
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'client_secret_basic',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    created_at: Date.now(),
  };

  await store.set(`dcr:client:${clientId}`, client);
}

/**
 * Inject provider refresh tokens into DCR store
 *
 * Creates a test DCR access token and maps it to the provider refresh token.
 * This allows the DCR test to skip the browser OAuth flow.
 *
 * @param store - DCR server's Keyv store
 * @param dcrAccessToken - Test DCR access token to use as key
 * @param providerTokens - Provider tokens (Microsoft)
 */
export async function injectProviderTokens(store: Keyv, dcrAccessToken: string, providerTokens: ProviderTokens): Promise<void> {
  // Store provider tokens mapped to DCR access token
  await dcrUtils.setProviderTokens(store, dcrAccessToken, providerTokens);
}

/**
 * Create ProviderTokens object from stored DCR token data
 *
 * @param tokenData - Stored DCR token data
 * @returns ProviderTokens object
 */
export function createProviderTokens(tokenData: DcrTokenData): ProviderTokens {
  return {
    accessToken: tokenData.providerAccessToken,
    refreshToken: tokenData.providerRefreshToken,
    expiresAt: tokenData.providerExpiresAt,
  };
}
