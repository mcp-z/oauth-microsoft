/**
 * DCR Router Refresh Tests (Microsoft)
 *
 * Tests the /oauth/token endpoint with grant_type=refresh_token
 * This validates the two-level refresh: DCR tokens AND underlying Microsoft provider tokens
 */

import '../lib/env-loader.ts';
import assert from 'assert';
import getPort from 'get-port';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../src/lib/dcr-utils.ts';
import type { AccessToken } from '../../src/types.ts';
import { startDcrTestServer } from '../lib/servers/dcr-test-server.ts';

// Read scope from environment variable (set in .env.test)
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} environment variable is required. Check .env.test`);
  }
  return value;
}

const MS_SCOPE = requireEnv('MS_SCOPE');

interface DcrTokenData {
  clientId: string;
  clientSecret: string;
  providerRefreshToken: string;
  providerAccessToken: string;
  providerExpiresAt: number;
}

/**
 * Load stored DCR tokens from test-setup
 */
async function loadDcrTokens(): Promise<DcrTokenData | undefined> {
  const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
  const dcrStore = new Keyv({
    store: new KeyvFile({ filename: dcrTokenPath }),
  });
  return (await dcrStore.get('microsoft')) as DcrTokenData | undefined;
}

describe('DCR Router Refresh Tests (Microsoft)', () => {
  let dcrCleanup: (() => Promise<void>) | undefined;
  let serverStore: Keyv;

  afterEach(async () => {
    if (dcrCleanup) {
      await dcrCleanup();
      dcrCleanup = undefined;
    }
  });

  it('should refresh DCR token and return new access token', async function () {
    this.timeout(30000);

    // Load stored tokens from test-setup
    const storedTokens = await loadDcrTokens();
    if (!storedTokens) {
      throw new Error('No stored DCR tokens found. Run npm run test:setup first to create test tokens.');
    }

    // DCR credentials - completely separate from loopback credentials
    const clientId = process.env.MS_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.MS_TEST_DCR_CLIENT_SECRET;
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID;
    if (!clientId || !tenantId) {
      throw new Error('MS_TEST_DCR_CLIENT_ID and MS_TEST_DCR_TENANT_ID environment variables required. Configure in .env.test');
    }

    // Get dynamic port to avoid conflicts (refresh tests don't need fixed URI)
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;

    // Start DCR test server
    const serverResult = await startDcrTestServer({
      port,
      baseUrl,
      scopes: [MS_SCOPE],
      clientId,
      ...(clientSecret && { clientSecret }),
      tenantId,
    });
    dcrCleanup = serverResult.close;
    serverStore = serverResult.store;

    // Register a client in the server's store (client_id and client_secret are generated)
    const registeredClient = await dcrUtils.registerClient(serverStore, {
      client_name: 'Test Refresh Client',
      redirect_uris: ['http://localhost:9999/callback'],
    });
    const testClientId = registeredClient.client_id;
    const testClientSecret = registeredClient.client_secret;
    if (!testClientSecret) throw new Error('registerClient must return client_secret');

    // Create initial access token with provider tokens in server store
    const initialAccessToken = `initial-access-token-${Date.now()}`;
    const refreshToken = `dcr-refresh-token-${Date.now()}`;
    const initialTokenData: AccessToken = {
      access_token: initialAccessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: MS_SCOPE,
      client_id: testClientId,
      providerTokens: {
        accessToken: storedTokens.providerAccessToken,
        refreshToken: storedTokens.providerRefreshToken,
        expiresAt: storedTokens.providerExpiresAt,
      },
      created_at: Date.now(),
    };

    await dcrUtils.setAccessToken(serverStore, initialAccessToken, initialTokenData);
    await dcrUtils.setRefreshToken(serverStore, refreshToken, initialTokenData);
    await dcrUtils.setProviderTokens(serverStore, initialAccessToken, initialTokenData.providerTokens);

    console.log('✅ Initial tokens set up in server store');

    // Call /oauth/token with grant_type=refresh_token
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: testClientId,
        client_secret: testClientSecret,
      }).toString(),
    });

    assert.ok(tokenResponse.ok, `Token refresh should succeed, got ${tokenResponse.status}`);

    const tokenData = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope?: string;
    };

    assert.ok(tokenData.access_token, 'Should return new access token');
    assert.notStrictEqual(tokenData.access_token, initialAccessToken, 'New token should be different from old');
    assert.strictEqual(tokenData.token_type, 'Bearer', 'Token type should be Bearer');
    console.log(`✅ New DCR access token: ${tokenData.access_token.substring(0, 20)}...`);

    // Verify new token works with /oauth/verify
    const verifyResponse = await fetch(`${baseUrl}/oauth/verify`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    assert.ok(verifyResponse.ok, 'New token should be verifiable');
    const verifyData = (await verifyResponse.json()) as {
      token: string;
      providerTokens: { accessToken: string; refreshToken?: string };
    };

    assert.strictEqual(verifyData.token, tokenData.access_token, 'Verify should return same token');
    assert.ok(verifyData.providerTokens.accessToken, 'Should have provider access token');
    console.log('✅ New token verified successfully');
    console.log('✅ Router refresh test passed!');
  });

  it('should fail refresh with invalid refresh_token', async function () {
    this.timeout(10000);

    // DCR credentials - completely separate from loopback credentials
    const clientId = process.env.MS_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.MS_TEST_DCR_CLIENT_SECRET;
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID;
    if (!clientId || !tenantId) {
      throw new Error('MS_TEST_DCR_CLIENT_ID and MS_TEST_DCR_TENANT_ID environment variables required. Configure in .env.test');
    }

    // Get dynamic port to avoid conflicts (refresh tests don't need fixed URI)
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;

    // Start DCR test server
    const serverResult = await startDcrTestServer({
      port,
      baseUrl,
      scopes: [MS_SCOPE],
      clientId,
      ...(clientSecret && { clientSecret }),
      tenantId,
    });
    dcrCleanup = serverResult.close;
    serverStore = serverResult.store;

    // Register a client (client_id and client_secret are generated)
    const registeredClient = await dcrUtils.registerClient(serverStore, {
      client_name: 'Test Invalid Refresh Client',
      redirect_uris: ['http://localhost:9999/callback'],
    });
    const testClientId = registeredClient.client_id;
    const testClientSecret = registeredClient.client_secret;
    if (!testClientSecret) throw new Error('registerClient must return client_secret');

    // Call /oauth/token with invalid refresh_token
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'invalid-refresh-token',
        client_id: testClientId,
        client_secret: testClientSecret,
      }).toString(),
    });

    assert.strictEqual(tokenResponse.status, 400, 'Should return 400 for invalid refresh token');

    const errorData = (await tokenResponse.json()) as { error: string; error_description?: string };
    assert.strictEqual(errorData.error, 'invalid_grant', 'Should return invalid_grant error');
    console.log('✅ Invalid refresh token correctly rejected');
  });
});
