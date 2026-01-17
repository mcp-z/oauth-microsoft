import assert from 'assert';
import express from 'express';
import getPort from 'get-port';
import Keyv from 'keyv';
import { createDcrRouter } from '../../src/index.ts';

describe('unit/dcr-router-scope-fallback', () => {
  it('uses server scopesSupported when client omits scope parameter', async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();
    const store = new Keyv();

    const serverScopes = ['openid', 'https://graph.microsoft.com/Mail.Read'];

    const dcrRouter = createDcrRouter({
      store,
      issuerUrl: baseUrl,
      baseUrl,
      scopesSupported: serverScopes,
      clientConfig: { clientId: 'test-ms-client-id', tenantId: 'common' },
    });

    app.use('/', dcrRouter);

    // Register a test client
    const clientId = 'dcr_test-client';
    const redirectUri = 'http://localhost:9999/callback';
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      redirect_uris: [redirectUri],
      client_name: 'Test Client',
    });

    const server = app.listen(port);
    try {
      // Make authorization request WITHOUT scope parameter (like codex does)
      const authUrl = new URL(`${baseUrl}/oauth/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('state', 'test-state');
      authUrl.searchParams.set('code_challenge', 'test-challenge');
      authUrl.searchParams.set('code_challenge_method', 'S256');
      // NOTE: No scope parameter - this is the bug scenario

      const response = await fetch(authUrl.toString(), { redirect: 'manual' });

      assert.strictEqual(response.status, 302, 'Should redirect to Microsoft OAuth');

      const location = response.headers.get('location');
      assert.ok(location, 'Should have Location header');

      const msUrl = new URL(location);
      const scopeParam = msUrl.searchParams.get('scope');

      // The scope should be the server's default scopes, not empty
      assert.ok(scopeParam, 'Microsoft OAuth URL should have scope parameter');
      assert.strictEqual(scopeParam, serverScopes.join(' '), `Scope should fall back to server's scopesSupported: "${serverScopes.join(' ')}" but got: "${scopeParam}"`);
    } finally {
      server.close();
    }
  });

  it('preserves client-provided scope when present', async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();
    const store = new Keyv();

    const serverScopes = ['openid', 'https://graph.microsoft.com/Mail.Read'];
    const clientScopes = 'openid profile';

    const dcrRouter = createDcrRouter({
      store,
      issuerUrl: baseUrl,
      baseUrl,
      scopesSupported: serverScopes,
      clientConfig: { clientId: 'test-ms-client-id', tenantId: 'common' },
    });

    app.use('/', dcrRouter);

    // Register a test client
    const clientId = 'dcr_test-client';
    const redirectUri = 'http://localhost:9999/callback';
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      redirect_uris: [redirectUri],
      client_name: 'Test Client',
    });

    const server = app.listen(port);
    try {
      // Make authorization request WITH scope parameter
      const authUrl = new URL(`${baseUrl}/oauth/authorize`);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('state', 'test-state');
      authUrl.searchParams.set('code_challenge', 'test-challenge');
      authUrl.searchParams.set('code_challenge_method', 'S256');
      authUrl.searchParams.set('scope', clientScopes);

      const response = await fetch(authUrl.toString(), { redirect: 'manual' });

      assert.strictEqual(response.status, 302, 'Should redirect to Microsoft OAuth');

      const location = response.headers.get('location');
      assert.ok(location, 'Should have Location header');

      const msUrl = new URL(location);
      const scopeParam = msUrl.searchParams.get('scope');

      // The scope should be the client's requested scopes
      assert.strictEqual(scopeParam, clientScopes, `Scope should use client-provided value: "${clientScopes}" but got: "${scopeParam}"`);
    } finally {
      server.close();
    }
  });
});
