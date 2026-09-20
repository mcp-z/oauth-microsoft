/**
 * DCR Router Refresh Tests (Microsoft)
 *
 * Tests the /oauth/token endpoint with grant_type=refresh_token
 * Calls real Microsoft endpoints to validate DCR and upstream provider token refresh.
 */

import '../lib/env-loader.ts';
import assert from 'assert';
import { randomUUID } from 'crypto';
import { mkdir, unlink } from 'fs/promises';
import getPort from 'get-port';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../src/lib/dcr-utils.ts';
import type { AccessToken } from '../../src/types.ts';
import { MS_SCOPE } from '../lib/constants.ts';
import { startDcrTestServer } from '../lib/servers/dcr-test-server.ts';

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
  try {
    return (await dcrStore.get('microsoft')) as DcrTokenData | undefined;
  } finally {
    await dcrStore.disconnect();
  }
}

describe('DCR Router Refresh Tests (Microsoft)', () => {
  let dcrCleanup: (() => Promise<void>) | undefined;
  let serverStore: Keyv;
  let activeServerStore: Keyv | undefined;
  let serverStorePath: string | undefined;

  afterEach(async () => {
    if (dcrCleanup) {
      await dcrCleanup();
      dcrCleanup = undefined;
    }
    if (activeServerStore) {
      await activeServerStore.disconnect();
      activeServerStore = undefined;
    }
    if (serverStorePath) {
      try {
        await unlink(serverStorePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      serverStorePath = undefined;
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
    await mkdir(path.resolve('.tmp'), { recursive: true });
    serverStorePath = path.resolve('.tmp', `dcr-refresh-${randomUUID()}.json`);
    const persistentStore = new Keyv({ store: new KeyvFile({ filename: serverStorePath }) });

    // Start DCR test server
    const serverResult = await startDcrTestServer({
      port,
      baseUrl,
      scopes: [MS_SCOPE],
      clientId,
      ...(clientSecret && { clientSecret }),
      tenantId,
      store: persistentStore,
    });
    dcrCleanup = serverResult.close;
    serverStore = serverResult.store;
    activeServerStore = serverStore;

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
    const renewed = await dcrUtils.getRefreshToken(serverStore, refreshToken);
    assert.ok(renewed, 'DCR refresh record must remain available');
    const dcrStore = new Keyv({ store: new KeyvFile({ filename: path.resolve('.tokens/dcr.json') }) });
    await dcrStore.set('microsoft', {
      ...storedTokens,
      providerAccessToken: renewed.providerTokens.accessToken,
      providerRefreshToken: renewed.providerTokens.refreshToken,
      providerExpiresAt: renewed.providerTokens.expiresAt,
    });
    await dcrStore.disconnect();
    assert.ok(renewed.providerTokens.refreshToken !== storedTokens.providerRefreshToken, 'DCR refresh record must retain the Microsoft replacement');
    const persistedAccess = await dcrUtils.getAccessToken(serverStore, tokenData.access_token);
    assert.ok(persistedAccess?.providerTokens.refreshToken === renewed.providerTokens.refreshToken, 'Access and refresh records must agree');
    assert.ok(tokenData.access_token !== initialAccessToken, 'New access token must differ from the previous token');
    assert.strictEqual(tokenData.token_type, 'Bearer', 'Token type should be Bearer');

    // Verify new token works with /oauth/verify
    const verifyResponse = await fetch(`${baseUrl}/oauth/verify`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    assert.ok(verifyResponse.ok, 'New token should be verifiable');
    const verifyData = (await verifyResponse.json()) as {
      token: string;
      providerTokens: { accessToken: string; refreshToken?: string };
    };

    assert.ok(verifyData.token === tokenData.access_token, 'Verification must return the submitted DCR access token');
    assert.ok(verifyData.providerTokens.accessToken, 'Should have provider access token');
    assert.ok(verifyData.providerTokens.refreshToken === renewed.providerTokens.refreshToken, 'Verification must return the persisted replacement');

    const secondResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: testClientId, client_secret: testClientSecret }),
    });
    assert.ok(secondResponse.ok, `A second DCR renewal must succeed (HTTP ${secondResponse.status})`);
    const secondTokenData = (await secondResponse.json()) as { access_token: string };
    assert.ok(secondTokenData.access_token, 'Second renewal must return a DCR access token');
    const second = await dcrUtils.getRefreshToken(serverStore, refreshToken);
    if (!second?.providerTokens.refreshToken) throw new Error('Second renewal must remain refreshable');
    const latestStore = new Keyv({ store: new KeyvFile({ filename: path.resolve('.tokens/dcr.json') }) });
    await latestStore.set('microsoft', {
      ...storedTokens,
      providerAccessToken: second.providerTokens.accessToken,
      providerRefreshToken: second.providerTokens.refreshToken,
      providerExpiresAt: second.providerTokens.expiresAt,
    });
    await latestStore.disconnect();
    assert.ok(second.providerTokens.refreshToken !== renewed.providerTokens.refreshToken, 'Second renewal must retain the next Microsoft replacement');

    const secondAccess = await dcrUtils.getAccessToken(serverStore, secondTokenData.access_token);
    if (!secondAccess) throw new Error('Second access-token record was not persisted');
    const expiringTokenData = {
      ...secondAccess,
      providerTokens: { ...secondAccess.providerTokens, expiresAt: Date.now() - 1000 },
    };
    await dcrUtils.setAccessToken(serverStore, secondTokenData.access_token, expiringTokenData);
    await dcrUtils.setRefreshToken(serverStore, refreshToken, expiringTokenData);
    await dcrUtils.setProviderTokens(serverStore, secondTokenData.access_token, expiringTokenData.providerTokens);
    const accessExpiryBefore = (await serverStore.get<AccessToken>(`dcr:access:${secondTokenData.access_token}`, { raw: true }))?.expires;
    const refreshExpiryBefore = (await serverStore.get<AccessToken>(`dcr:refresh:${refreshToken}`, { raw: true }))?.expires;
    const providerExpiryBefore = (await serverStore.get(`dcr:provider:${secondTokenData.access_token}`, { raw: true }))?.expires;
    if (accessExpiryBefore === undefined || refreshExpiryBefore === undefined || providerExpiryBefore === undefined) {
      throw new Error('Expected file-backed DCR records to include expiry metadata');
    }

    const requestRefreshResponse = await fetch(`${baseUrl}/oauth/verify`, {
      headers: { Authorization: `Bearer ${secondTokenData.access_token}` },
    });
    assert.ok(requestRefreshResponse.ok, 'Request-time provider refresh must verify the DCR token');
    const requestRefreshData = (await requestRefreshResponse.json()) as {
      token: string;
      providerTokens: { accessToken: string; refreshToken?: string; expiresAt?: number };
    };
    const requestRenewal = await dcrUtils.getRefreshToken(serverStore, refreshToken);
    if (!requestRenewal) throw new Error('DCR refresh record was not persisted after provider refresh');
    const requestStore = new Keyv({ store: new KeyvFile({ filename: path.resolve('.tokens/dcr.json') }) });
    try {
      await requestStore.set('microsoft', {
        ...storedTokens,
        providerAccessToken: requestRenewal.providerTokens.accessToken,
        providerRefreshToken: requestRenewal.providerTokens.refreshToken,
        providerExpiresAt: requestRenewal.providerTokens.expiresAt,
      });
    } finally {
      await requestStore.disconnect();
    }

    const accessAfter = await serverStore.get<AccessToken>(`dcr:access:${secondTokenData.access_token}`, { raw: true });
    const refreshAfter = await serverStore.get<AccessToken>(`dcr:refresh:${refreshToken}`, { raw: true });
    const providerAfter = await serverStore.get(`dcr:provider:${secondTokenData.access_token}`, { raw: true });
    if (accessAfter?.expires === undefined || refreshAfter?.expires === undefined || providerAfter?.expires === undefined) {
      throw new Error('Refreshed file-backed DCR records must retain expiry metadata');
    }

    assert.ok(requestRefreshData.token === secondTokenData.access_token, 'Verification must return the submitted DCR access token');
    assert.ok(requestRenewal.created_at === secondAccess.created_at, 'Provider refresh must preserve DCR token created_at');
    assert.ok(requestRenewal.expires_in === secondAccess.expires_in, 'Provider refresh must preserve DCR token expires_in');
    assert.ok(accessAfter.expires <= accessExpiryBefore + 500, 'Verification must not extend the access-token store expiry');
    assert.ok(refreshAfter.expires <= refreshExpiryBefore + 500, 'Verification must not extend the refresh-token store expiry');
    assert.ok(providerAfter.expires <= providerExpiryBefore + 500, 'Verification must not extend the provider-token index expiry');
    assert.ok(requestRefreshData.providerTokens.accessToken === requestRenewal.providerTokens.accessToken, 'Verification must return the persisted provider access token');
    assert.ok(requestRefreshData.providerTokens.refreshToken === requestRenewal.providerTokens.refreshToken, 'Verification must return the persisted provider refresh token');

    const graphResponse = await fetch('https://graph.microsoft.com/v1.0/me?$select=id', {
      headers: { Authorization: `Bearer ${requestRefreshData.providerTokens.accessToken}` },
      signal: AbortSignal.timeout(30000),
    });
    assert.ok(graphResponse.ok, `DCR renewed credentials must authorize Graph /me (HTTP ${graphResponse.status})`);
    await dcrUtils.setRefreshToken(serverStore, refreshToken, {
      ...requestRenewal,
      providerTokens: { ...requestRenewal.providerTokens, refreshToken: 'invalid-provider-refresh-token' },
    });
    const refusedResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: testClientId, client_secret: testClientSecret }),
    });
    assert.strictEqual(refusedResponse.status, 502, 'An upstream refresh failure must not issue a successful DCR response');
    const refused = (await refusedResponse.json()) as { error?: string; access_token?: string };
    assert.strictEqual(refused.error, 'server_error');
    assert.ok(refused.access_token === undefined, 'An upstream refresh failure must not return a DCR access token');
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
    activeServerStore = serverStore;

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
