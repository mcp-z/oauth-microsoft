/**
 * DcrOAuthProvider Unit Tests
 *
 * Tests the stateless DCR provider pattern with token refresh
 */

import '../../lib/env-loader.ts';
import assert from 'assert';
import type { Server } from 'http';
import { createServer } from 'http';
import type { DcrOAuthProviderConfig } from '../../../src/providers/dcr.ts';
import { DcrOAuthProvider } from '../../../src/providers/dcr.ts';
import type { ProviderTokens } from '../../../src/types.ts';

describe('DcrOAuthProvider', () => {
  let server: Server;
  let tenantId: string;
  let provider: DcrOAuthProvider;

  before(async () => {
    // Create mock Microsoft token endpoint
    return new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        let body = '';

        req.on('data', (chunk) => {
          body += chunk.toString();
        });

        req.on('end', () => {
          // Only respond to /token endpoint
          if (req.url !== '/token') {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'not_found' }));
            return;
          }

          const params = new URLSearchParams(body);
          const grantType = params.get('grant_type');
          const refreshToken = params.get('refresh_token');

          if (grantType === 'refresh_token' && refreshToken === 'valid_refresh_token') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                access_token: 'refreshed_access_token',
                expires_in: 3600,
                scope: 'Mail.Read Mail.Send',
              })
            );
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid refresh token' }));
          }
        });
      });

      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address !== 'string') {
          tenantId = 'common'; // Use standard tenant ID for production code path

          const config: DcrOAuthProviderConfig = {
            clientId: 'test_client_id',
            clientSecret: 'test_client_secret',
            tenantId,
            scope: 'Mail.Read Mail.Send',
            tokenUrl: `http://127.0.0.1:${address.port}/token`, // Point to mock server
            verifyEndpoint: 'http://test.invalid/oauth/verify', // Not used in these tests
            logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
          };

          provider = new DcrOAuthProvider(config);
          resolve();
        }
      });
    });
  });

  after(() => {
    server.close();
  });

  it('creates auth provider from valid tokens', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'valid_access_token',
      refreshToken: 'valid_refresh_token',
      expiresAt: Date.now() + 3600000, // Valid for 1 hour
      scope: 'Mail.Read',
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    assert.strictEqual(accessToken, 'valid_access_token');
  });

  it('refreshes expired token automatically', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      refreshToken: 'valid_refresh_token',
      expiresAt: Date.now() - 1000, // Expired 1 second ago
      scope: 'Mail.Read',
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    // Should return refreshed token
    assert.strictEqual(accessToken, 'refreshed_access_token');
  });

  it('throws error when token expired and no refresh token', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      expiresAt: Date.now() - 1000, // Expired
      // No refresh token
    };

    const auth = provider.toAuthProvider(tokens);

    await assert.rejects(async () => {
      await auth.getAccessToken();
    }, /Access token expired and no refresh token available/);
  });

  it('throws error when refresh fails', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      refreshToken: 'invalid_refresh_token',
      expiresAt: Date.now() - 1000, // Expired
    };

    const auth = provider.toAuthProvider(tokens);

    await assert.rejects(async () => {
      await auth.getAccessToken();
    }, /Token refresh failed/);
  });

  it('handles tokens without expiry (assumes valid)', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'no_expiry_token',
      // No expiresAt field
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    assert.strictEqual(accessToken, 'no_expiry_token');
  });

  it('supports multiple auth providers from same tokens', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'shared_token',
      expiresAt: Date.now() + 3600000,
    };

    const auth1 = provider.toAuthProvider(tokens);
    const auth2 = provider.toAuthProvider(tokens);

    const token1 = await auth1.getAccessToken();
    const token2 = await auth2.getAccessToken();

    // Both should return the same token (stateless)
    assert.strictEqual(token1, 'shared_token');
    assert.strictEqual(token2, 'shared_token');
  });
});

// Integration tests with real Microsoft endpoints (require tokens from test-setup)
describe('DcrOAuthProvider - Integration with Microsoft APIs', () => {
  it('should refresh provider tokens with real Microsoft endpoint', async function () {
    this.timeout(30000);

    // Load stored DCR tokens from test-setup
    const path = await import('path');
    const Keyv = (await import('keyv')).default;
    const { KeyvFile } = await import('keyv-file');

    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({
      store: new KeyvFile({ filename: dcrTokenPath }),
    });

    interface DcrTokenData {
      clientId: string;
      clientSecret: string;
      providerRefreshToken: string;
      providerAccessToken: string;
      providerExpiresAt: number;
    }

    const storedTokens = (await dcrStore.get('microsoft')) as DcrTokenData | undefined;
    if (!storedTokens || !storedTokens.providerRefreshToken) {
      console.log('\n⚠️  Skipped: No stored DCR tokens found. Run npm run test:setup first.\n');
      this.skip();
      return;
    }

    const clientId = process.env.MS_CLIENT_ID;
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID || 'common';
    if (!clientId) {
      console.log('\n⚠️  Skipped: MS_CLIENT_ID not configured.\n');
      this.skip();
      return;
    }

    const realProvider = new DcrOAuthProvider({
      clientId,
      ...(process.env.MS_TEST_DCR_CLIENT_SECRET && { clientSecret: process.env.MS_TEST_DCR_CLIENT_SECRET }),
      tenantId,
      scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read',
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
    });

    // Test refresh with real Microsoft endpoint
    console.log('🔄 Refreshing tokens with real Microsoft endpoint...');
    const refreshedTokens = await realProvider.refreshAccessToken(storedTokens.providerRefreshToken);

    assert.ok(refreshedTokens.accessToken, 'Should return new access token');
    assert.ok(refreshedTokens.accessToken !== storedTokens.providerAccessToken || refreshedTokens.expiresAt, 'Should have new token or fresh expiry');
    console.log(`✅ Refreshed token: ${refreshedTokens.accessToken.substring(0, 20)}...`);

    // Verify the refreshed token works by calling getUserEmail
    console.log('🔍 Verifying refreshed token with Microsoft Graph API...');
    const email = await realProvider.getUserEmail(refreshedTokens);
    assert.ok(email, 'Should get user email with refreshed token');
    assert.ok(email.includes('@'), 'Email should be valid format');
    console.log(`✅ Verified - user email: ${email}`);
  });

  it('should fail refresh with invalid token', async function () {
    this.timeout(10000);

    const clientId = process.env.MS_CLIENT_ID;
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID || 'common';
    if (!clientId) {
      console.log('\n⚠️  Skipped: MS_CLIENT_ID not configured.\n');
      this.skip();
      return;
    }

    const realProvider = new DcrOAuthProvider({
      clientId,
      ...(process.env.MS_TEST_DCR_CLIENT_SECRET && { clientSecret: process.env.MS_TEST_DCR_CLIENT_SECRET }),
      tenantId,
      scope: 'https://graph.microsoft.com/Mail.Read',
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
    });

    // Test refresh with invalid token
    await assert.rejects(
      async () => {
        await realProvider.refreshAccessToken('invalid_refresh_token_12345');
      },
      /Token refresh failed/,
      'Should throw error for invalid refresh token'
    );
    console.log('✅ Invalid refresh token correctly rejected by Microsoft');
  });
});
