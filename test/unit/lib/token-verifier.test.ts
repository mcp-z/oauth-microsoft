/**
 * DcrTokenVerifier Unit Tests
 *
 * Note: These tests use a mock HTTP server since we're testing the verifier
 * in isolation without a full DCR router setup.
 */

import assert from 'assert';
import type { Server } from 'http';
import { createServer } from 'http';
import type { AuthInfo } from '../../../src/lib/token-verifier.ts';
import { DcrTokenVerifier } from '../../../src/lib/token-verifier.ts';

describe('DcrTokenVerifier', () => {
  let server: Server;
  let verifyUrl: string;
  let verifier: DcrTokenVerifier;

  before(async () => {
    // Create mock verification endpoint
    return new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Missing or invalid Authorization header' }));
          return;
        }

        const token = authHeader.substring(7);

        if (token === 'valid_token') {
          const authInfo: AuthInfo = {
            token,
            clientId: 'test_client',
            scopes: ['Mail.Read', 'Mail.Send'],
            expiresAt: Date.now() + 3600000,
            providerTokens: {
              accessToken: 'microsoft_access_token',
              refreshToken: 'microsoft_refresh_token',
              expiresAt: Date.now() + 3600000,
              scope: 'Mail.Read Mail.Send',
            },
          };

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(authInfo));
        } else if (token === 'expired_token') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_token', error_description: 'Access token has expired' }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_token', error_description: 'Unknown or expired access token' }));
        }
      });

      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address !== 'string') {
          verifyUrl = `http://127.0.0.1:${address.port}/oauth/verify`;
          verifier = new DcrTokenVerifier(verifyUrl);
          resolve();
        }
      });
    });
  });

  after(() => {
    server.close();
  });

  it('verifies a valid token', async () => {
    const authInfo = await verifier.verifyAccessToken('valid_token');

    assert.ok(authInfo);
    assert.strictEqual(authInfo.token, 'valid_token');
    assert.strictEqual(authInfo.clientId, 'test_client');
    assert.deepStrictEqual(authInfo.scopes, ['Mail.Read', 'Mail.Send']);
    assert.ok(authInfo.expiresAt > Date.now());
    assert.ok(authInfo.providerTokens);
    assert.strictEqual(authInfo.providerTokens.accessToken, 'microsoft_access_token');
  });

  it('throws error for expired token', async () => {
    await assert.rejects(async () => {
      await verifier.verifyAccessToken('expired_token');
    }, /Access token has expired/);
  });

  it('throws error for invalid token', async () => {
    await assert.rejects(async () => {
      await verifier.verifyAccessToken('invalid_token');
    }, /Unknown or expired access token/);
  });

  it('throws error for missing token', async () => {
    await assert.rejects(async () => {
      await verifier.verifyAccessToken('');
    }, /Token verification failed/);
  });
});
