/**
 * DCR Provider Token Utils Unit Tests
 */

import assert from 'assert';
import Keyv from 'keyv';
import * as dcrUtils from '../../../src/lib/dcr-utils.ts';
import type { ProviderTokens } from '../../../src/types.ts';

describe('DCR Provider Token Utils', () => {
  let store: Keyv;

  beforeEach(() => {
    // Use in-memory store for testing
    store = new Keyv();
  });

  afterEach(async () => {
    await store.clear();
  });

  it('stores and retrieves provider tokens', async () => {
    const dcrToken = 'test_dcr_token';
    const providerTokens: ProviderTokens = {
      accessToken: 'microsoft_access_token',
      refreshToken: 'microsoft_refresh_token',
      expiresAt: Date.now() + 3600000,
      scope: 'Mail.Read',
    };

    await dcrUtils.setProviderTokens(store, dcrToken, providerTokens);
    const retrieved = await dcrUtils.getProviderTokens(store, dcrToken);

    assert.ok(retrieved);
    assert.strictEqual(retrieved.accessToken, providerTokens.accessToken);
    assert.strictEqual(retrieved.refreshToken, providerTokens.refreshToken);
    assert.strictEqual(retrieved.expiresAt, providerTokens.expiresAt);
    assert.strictEqual(retrieved.scope, providerTokens.scope);
  });

  it('returns undefined for non-existent token', async () => {
    const retrieved = await dcrUtils.getProviderTokens(store, 'non_existent_token');
    assert.strictEqual(retrieved, undefined);
  });

  it('deletes provider tokens', async () => {
    const dcrToken = 'test_delete_token';
    const providerTokens: ProviderTokens = {
      accessToken: 'test_access',
      refreshToken: 'test_refresh',
    };

    await dcrUtils.setProviderTokens(store, dcrToken, providerTokens);
    const beforeDelete = await dcrUtils.getProviderTokens(store, dcrToken);
    assert.ok(beforeDelete);

    await dcrUtils.deleteProviderTokens(store, dcrToken);
    const afterDelete = await dcrUtils.getProviderTokens(store, dcrToken);
    assert.strictEqual(afterDelete, undefined);
  });

  it('handles tokens without optional fields', async () => {
    const dcrToken = 'minimal_token';
    const providerTokens: ProviderTokens = {
      accessToken: 'only_access_token',
    };

    await dcrUtils.setProviderTokens(store, dcrToken, providerTokens);
    const retrieved = await dcrUtils.getProviderTokens(store, dcrToken);

    assert.ok(retrieved);
    assert.strictEqual(retrieved.accessToken, providerTokens.accessToken);
    assert.strictEqual(retrieved.refreshToken, undefined);
    assert.strictEqual(retrieved.expiresAt, undefined);
    assert.strictEqual(retrieved.scope, undefined);
  });
});
