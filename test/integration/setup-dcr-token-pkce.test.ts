import '../lib/env-loader.ts';
import { randomUUID } from 'node:crypto';
import { generatePKCE } from '@mcp-z/oauth';
import { createDcrRouter } from '@mcp-z/oauth-microsoft';
import assert from 'assert';
import express from 'express';
import Keyv from 'keyv';
import type { Socket } from 'net';
import { listenOnFreePort } from '../lib/listen-on-free-port.ts';
import { assertDcrCallbackState, createDcrAuthorizationUrl, createDcrTokenBody } from '../lib/setup-dcr-token.ts';

describe('integration/setup-dcr-token-pkce', () => {
  it('uses PKCE accepted by the real DCR authorize and token endpoints', async () => {
    const redirectUri = 'http://localhost:51746/callback';
    const clientId = `dcr_${randomUUID()}`;
    const clientSecret = randomUUID();
    const store = new Keyv();
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      client_name: 'Setup PKCE integration test',
    });

    const app = express();
    const { server, port } = await listenOnFreePort(app, 'localhost');
    const baseUrl = `http://localhost:${port}`;
    app.use(
      '/',
      createDcrRouter({
        store,
        issuerUrl: baseUrl,
        baseUrl,
        scopesSupported: ['openid', 'email'],
        clientConfig: { clientId: 'dummy-upstream-client', tenantId: 'common' },
      })
    );
    const connections = new Set<Socket>();
    server.on('connection', (socket) => {
      connections.add(socket);
      socket.once('close', () => connections.delete(socket));
    });

    try {
      const { verifier, challenge } = generatePKCE();
      const state = randomUUID();
      const authorizationUrl = createDcrAuthorizationUrl({
        authorizationEndpoint: `${baseUrl}/oauth/authorize`,
        clientId,
        redirectUri,
        scope: 'openid email',
        state,
        codeChallenge: challenge,
      });
      const authorization = await fetch(authorizationUrl, { redirect: 'manual' });
      assert.strictEqual(authorization.status, 302);

      const storeCode = async (code: string) => {
        await store.set(`dcr:authcode:${code}`, {
          code,
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: 'openid email',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          providerTokens: { accessToken: 'dummy-provider-token', expiresAt: Date.now() + 3_600_000 },
          created_at: Date.now(),
          expires_at: Date.now() + 600_000,
        });
      };
      const exchange = (code: string, codeVerifier: string) =>
        fetch(`${baseUrl}/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: createDcrTokenBody({ code, redirectUri, clientId, clientSecret, codeVerifier }),
        });

      const rejectedCode = randomUUID();
      await storeCode(rejectedCode);
      const rejected = await exchange(rejectedCode, `${verifier}-wrong`);
      assert.strictEqual(rejected.status, 400);
      assert.strictEqual(((await rejected.json()) as { error?: string }).error, 'invalid_grant');

      const acceptedCode = randomUUID();
      await storeCode(acceptedCode);
      const accepted = await exchange(acceptedCode, verifier);
      assert.strictEqual(accepted.status, 200);
      assert.ok(((await accepted.json()) as { access_token?: string }).access_token);

      assert.doesNotThrow(() => assertDcrCallbackState(state, state));
      assert.throws(() => assertDcrCallbackState(undefined, state), /state mismatch/);
      assert.throws(() => assertDcrCallbackState(randomUUID(), state), /state mismatch/);
    } finally {
      const closed = new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
      if (typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      } else {
        for (const socket of connections) socket.destroy();
      }
      await closed;
    }
  });
});
