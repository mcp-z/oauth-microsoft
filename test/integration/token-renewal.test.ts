// Calls Microsoft's token endpoint and Graph /me using the existing test accounts.
// Successful renewals are saved to the original store so replacement credentials survive the run.
import '../lib/env-loader.ts';
import { type CachedToken, getToken, listAccountIds, setToken } from '@mcp-z/oauth';
import assert from 'assert';
import { mkdir, mkdtemp, rmdir, unlink } from 'fs/promises';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import path from 'path';
import { DeviceCodeProvider } from '../../src/providers/device-code.ts';
import { LoopbackOAuthProvider } from '../../src/providers/loopback-oauth.ts';
import { createConfig } from '../lib/config.ts';
import { MS_SCOPE } from '../lib/constants.ts';
import { logger } from '../lib/test-utils.ts';
import { getRefreshedToken } from '../lib/token-refresh.ts';

const config = createConfig();

describe('Microsoft unattended token renewal (live)', () => {
  it('fails an invalid loopback refresh in headless mode without requesting consent', async () => {
    const store = new Keyv();
    const params = { accountId: 'invalid-test-account', service: 'outlook' };
    await setToken(store, params, { accessToken: 'expired', refreshToken: 'invalid-refresh-token', expiresAt: 1 });
    const provider = new LoopbackOAuthProvider({ ...config, service: 'outlook', scope: MS_SCOPE, logger, tokenStore: store, headless: true });
    try {
      await assert.rejects(() => provider.getAccessToken(params.accountId), /Token refresh failed in headless mode/);
      assert.strictEqual((await getToken<CachedToken>(store, params))?.refreshToken, 'invalid-refresh-token');
    } finally {
      await store.disconnect();
    }
  });

  for (const flow of ['loopback', 'device-code', 'test-helper'] as const) {
    it(`${flow} renews expired credentials and uses the persisted replacement after reopening`, async () => {
      const original = new Keyv({ store: new KeyvFile({ filename: path.resolve('.tokens/test/store.json') }) });
      const accounts = await listAccountIds(original, 'outlook');
      const accountId = flow === 'device-code' ? 'device-code' : accounts.find((id) => id !== 'device-code');
      assert.ok(accountId, 'No existing Outlook test account; run npm run test:setup');
      const params = { accountId, service: 'outlook' };
      const initial = await getToken<CachedToken>(original, params);
      assert.ok(initial?.refreshToken, 'Existing account needs a refresh token');
      await mkdir(path.resolve('.tmp'), { recursive: true });
      const directory = await mkdtemp(path.resolve('.tmp/token-renewal-'));
      const filename = path.join(directory, 'store.json');
      let store = new Keyv({ store: new KeyvFile({ filename }) });
      const renew = async (): Promise<string> => {
        if (flow === 'test-helper') return getRefreshedToken(store, accountId, 'outlook', config.clientId, config.tenantId, MS_SCOPE, config.clientSecret);
        const options = { ...config, service: 'outlook', scope: MS_SCOPE, logger, tokenStore: store, headless: true };
        const provider = flow === 'device-code' ? new DeviceCodeProvider(options) : new LoopbackOAuthProvider(options);
        return provider.getAccessToken(accountId);
      };

      try {
        await setToken(store, params, { ...initial, expiresAt: 1 });
        let previousRefresh = initial.refreshToken;
        for (let round = 0; round < 2; round++) {
          const accessToken = await renew();
          const refreshed = await getToken<CachedToken>(store, params);
          assert.ok(refreshed?.refreshToken, 'Renewal must preserve a refresh credential');
          // Persist before assertions and Graph calls, even if later verification fails.
          await setToken(original, params, refreshed);
          assert.ok(refreshed.accessToken === accessToken, 'Returned access token must match the stored credential');
          assert.ok(refreshed.refreshToken !== previousRefresh, 'Microsoft replacement refresh token must be retained');
          assert.ok(refreshed.expiresAt !== undefined && refreshed.expiresAt > Date.now(), 'Renewal must advance expiry');
          previousRefresh = refreshed.refreshToken;
          await store.disconnect();
          store = new Keyv({ store: new KeyvFile({ filename }) });
          const reopened = await getToken<CachedToken>(store, params);
          assert.ok(reopened?.refreshToken === previousRefresh, 'Replacement must survive reopening the file store');
          if (round === 0) await setToken(store, params, { ...refreshed, expiresAt: 1 });
          else {
            const response = await fetch('https://graph.microsoft.com/v1.0/me?$select=id', { headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(30000) });
            assert.ok(response.ok, `Renewed credential must authorize Graph /me (HTTP ${response.status})`);
          }
        }
      } finally {
        await store.disconnect();
        await original.disconnect();
        await unlink(filename);
        await rmdir(directory);
      }
    });
  }
});
