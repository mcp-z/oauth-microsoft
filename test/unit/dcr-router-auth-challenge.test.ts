import assert from 'assert';
import express from 'express';
import getPort from 'get-port';
import Keyv from 'keyv';
import { createDcrRouter } from '../../src/index.ts';

describe('unit/dcr-router-auth-challenge', () => {
  it('responds with WWW-Authenticate on missing bearer token', async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();

    const dcrRouter = createDcrRouter({
      store: new Keyv(),
      issuerUrl: baseUrl,
      baseUrl,
      scopesSupported: ['read'],
      clientConfig: { clientId: 'test-client-id', tenantId: 'common' },
    });

    app.use('/', dcrRouter);

    const server = app.listen(port);
    try {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', params: {}, id: 1 }),
      });

      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.headers.get('www-authenticate'), `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);

      const payload = (await response.json()) as { error?: { code?: number } };
      assert.strictEqual(payload.error?.code, -32600);
    } finally {
      server.close();
    }
  });
});
