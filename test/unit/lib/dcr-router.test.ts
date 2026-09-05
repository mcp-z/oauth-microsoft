import { createDcrRouter } from '@mcp-z/oauth-microsoft';
import assert from 'assert';
import express from 'express';
import getPort from 'get-port';
import Keyv from 'keyv';

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

describe('unit/dcr-router-pkce-s256-only', () => {
  const setup = async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();
    const store = new Keyv();

    const dcrRouter = createDcrRouter({
      store,
      issuerUrl: baseUrl,
      baseUrl,
      scopesSupported: ['openid'],
      clientConfig: { clientId: 'test-ms-client-id' },
    });
    app.use('/', dcrRouter);

    const clientId = 'dcr_pkce-client';
    const clientSecret = 'test-client-secret';
    const redirectUri = 'http://localhost:9999/callback';
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      client_name: 'PKCE Test Client',
    });

    return { baseUrl, store, clientId, clientSecret, redirectUri, server: app.listen(port) };
  };

  const authorizeUrl = (baseUrl: string, clientId: string, redirectUri: string, method?: string) => {
    const url = new URL(`${baseUrl}/oauth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('code_challenge', 'test-challenge');
    if (method !== undefined) url.searchParams.set('code_challenge_method', method);
    return url.toString();
  };

  it('advertises S256 only in authorization server metadata', async () => {
    const { baseUrl, server } = await setup();
    try {
      const response = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
      const metadata = (await response.json()) as { code_challenge_methods_supported?: string[] };

      assert.deepStrictEqual(metadata.code_challenge_methods_supported, ['S256'], 'plain is a downgrade vector and must not be advertised');
    } finally {
      server.close();
    }
  });

  it('rejects code_challenge_method=plain at the authorize endpoint', async () => {
    const { baseUrl, clientId, redirectUri, server } = await setup();
    try {
      const response = await fetch(authorizeUrl(baseUrl, clientId, redirectUri, 'plain'), { redirect: 'manual' });

      assert.strictEqual(response.status, 400, 'plain must be refused, not honored');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_request');
    } finally {
      server.close();
    }
  });

  it('accepts code_challenge_method=S256 at the authorize endpoint', async () => {
    const { baseUrl, clientId, redirectUri, server } = await setup();
    try {
      const response = await fetch(authorizeUrl(baseUrl, clientId, redirectUri, 'S256'), { redirect: 'manual' });

      assert.strictEqual(response.status, 302, 'S256 is the supported method and must still redirect');
    } finally {
      server.close();
    }
  });

  it('rejects an omitted code_challenge_method, which RFC 7636 defaults to plain', async () => {
    const { baseUrl, clientId, redirectUri, server } = await setup();
    try {
      // An absent method is the plain downgrade spelled differently, so it must fail here
      // rather than surviving the browser round trip and failing at token exchange.
      const response = await fetch(authorizeUrl(baseUrl, clientId, redirectUri), { redirect: 'manual' });

      assert.strictEqual(response.status, 400, 'an omitted method implies plain and must be refused');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_request');
    } finally {
      server.close();
    }
  });

  it('refuses to verify a stored challenge whose method is not S256', async () => {
    const { baseUrl, store, clientId, clientSecret, redirectUri, server } = await setup();
    try {
      // A code minted before the authorize-endpoint guard existed: plain method, verifier
      // equal to the challenge. Previously this verified successfully.
      const code = 'dcr_legacy_plain_code';
      await store.set(`dcr:authcode:${code}`, {
        code,
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: 'openid',
        code_challenge: 'plain-verifier',
        code_challenge_method: 'plain',
        providerTokens: { accessToken: 'test-access-token', refreshToken: 'test-refresh-token', expiresAt: Math.floor(Date.now() / 1000) + 3600 },
        created_at: Date.now(),
        expires_at: Date.now() + 600000,
      });

      const response = await fetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: 'plain-verifier',
        }),
      });

      assert.strictEqual(response.status, 400, 'a plain challenge must not verify');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_grant');
    } finally {
      server.close();
    }
  });
});
