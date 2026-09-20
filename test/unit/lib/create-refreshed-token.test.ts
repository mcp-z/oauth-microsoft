import '../../lib/env-loader.ts';
import assert from 'assert';
import { createRefreshedToken } from '../../../src/lib/create-refreshed-token.ts';

describe('createRefreshedToken', () => {
  it('retains replacement credentials and converts their expiry to an absolute time', () => {
    const before = Date.now();
    const token = createRefreshedToken({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600, scope: 'User.Read' }, 'old-refresh');
    assert.strictEqual(token.accessToken, 'new-access');
    assert.strictEqual(token.refreshToken, 'new-refresh');
    assert.strictEqual(token.scope, 'User.Read');
    assert.ok(token.expiresAt !== undefined && token.expiresAt >= before + 3600000 && token.expiresAt <= Date.now() + 3600000);
  });

  it('preserves the existing refresh credential when no replacement is issued', () => {
    assert.deepStrictEqual(createRefreshedToken({ access_token: 'new-access' }, 'old-refresh'), { accessToken: 'new-access', refreshToken: 'old-refresh' });
    assert.strictEqual(createRefreshedToken({ access_token: 'new-access', refresh_token: '' }, 'old-refresh').refreshToken, 'old-refresh');
  });

  it('preserves a zero expiry as already expiring', () => {
    const before = Date.now();
    const token = createRefreshedToken({ access_token: 'expired', expires_in: 0 }, 'refresh');
    assert.ok(token.expiresAt !== undefined && token.expiresAt >= before && token.expiresAt <= Date.now());
  });
});
