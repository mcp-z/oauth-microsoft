import '../../lib/env-loader.ts';
import { createDcrRouter } from '@mcp-z/oauth-microsoft';
import assert from 'assert';
import { createHash } from 'crypto';
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

describe('unit/dcr-router-protected-resource-metadata', () => {
  // Both RFC 9728 documents describe one protected resource, so both must name
  // it identically. They did not: the root document answered `baseUrl`, which
  // is the deployment root and not a protected resource at all. A client reading
  // that one audience-binds its token (RFC 8707) to the wrong identifier, and an
  // authorization server that validates the indicator rejects it.
  it('names the MCP endpoint identically at the root and sub-path locations', async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();

    app.use(
      '/',
      createDcrRouter({
        store: new Keyv(),
        issuerUrl: baseUrl,
        baseUrl,
        scopesSupported: ['read'],
        clientConfig: { clientId: 'test-client-id' },
      })
    );

    const server = app.listen(port);
    try {
      const read = async (path: string) => (await (await fetch(`${baseUrl}${path}`)).json()) as { resource?: string };
      const root = await read('/.well-known/oauth-protected-resource');
      const subPath = await read('/.well-known/oauth-protected-resource/mcp');

      assert.strictEqual(root.resource, `${baseUrl}/mcp`, 'root document must name the MCP endpoint');
      assert.strictEqual(subPath.resource, `${baseUrl}/mcp`);
      assert.strictEqual(root.resource, subPath.resource, 'one resource, one identifier');
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

describe('unit/dcr-router-pkce-required', () => {
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

    const clientId = 'dcr_pkce_required-client';
    const clientSecret = 'test-client-secret';
    const redirectUri = 'http://localhost:9999/callback';
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: [redirectUri],
      client_name: 'PKCE Required Test Client',
    });

    return { baseUrl, store, clientId, clientSecret, redirectUri, server: app.listen(port) };
  };

  const s256 = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');

  const storeAuthCode = async (store: Keyv, code: string, clientId: string, redirectUri: string, challenge?: string, method?: string) => {
    await store.set(`dcr:authcode:${code}`, {
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid',
      ...(challenge && { code_challenge: challenge }),
      ...(method && { code_challenge_method: method }),
      providerTokens: { accessToken: 'test-access-token', refreshToken: 'test-refresh-token', expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      created_at: Date.now(),
      expires_at: Date.now() + 600000,
    });
  };

  it('rejects an authorize request with no code_challenge', async () => {
    const { baseUrl, clientId, redirectUri, server } = await setup();
    try {
      const url = new URL(`${baseUrl}/oauth/authorize`);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);

      const response = await fetch(url.toString(), { redirect: 'manual' });

      assert.strictEqual(response.status, 400, 'a code minted without a challenge has no proof binding and must not be minted');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_request');
    } finally {
      server.close();
    }
  });

  it('still accepts an authorize request with code_challenge_method=S256', async () => {
    const { baseUrl, clientId, redirectUri, server } = await setup();
    try {
      const url = new URL(`${baseUrl}/oauth/authorize`);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('code_challenge', s256('dcr-test-code-verifier'));
      url.searchParams.set('code_challenge_method', 'S256');

      const response = await fetch(url.toString(), { redirect: 'manual' });

      assert.strictEqual(response.status, 302, 'a well-formed PKCE request must still redirect');
    } finally {
      server.close();
    }
  });

  it('rejects a token request that omits the code_verifier', async () => {
    const { baseUrl, store, clientId, clientSecret, redirectUri, server } = await setup();
    try {
      const code = 'dcr_pkce_required_missing-verifier';
      await storeAuthCode(store, code, clientId, redirectUri, s256('dcr-test-code-verifier'), 'S256');

      const response = await fetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
        }),
      });

      assert.strictEqual(response.status, 400, 'a challenge-bound code must not be redeemable without its verifier');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_request');
    } finally {
      server.close();
    }
  });

  it('rejects a token request with an incorrect code_verifier', async () => {
    const { baseUrl, store, clientId, clientSecret, redirectUri, server } = await setup();
    try {
      const code = 'dcr_pkce_required_wrong-verifier';
      await storeAuthCode(store, code, clientId, redirectUri, s256('dcr-test-code-verifier'), 'S256');

      const response = await fetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: 'a-different-verifier',
        }),
      });

      assert.strictEqual(response.status, 400, 'a wrong verifier proves nothing and must not be redeemed');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_grant');
    } finally {
      server.close();
    }
  });

  it('rejects a code minted before PKCE became mandatory', async () => {
    const { baseUrl, store, clientId, clientSecret, redirectUri, server } = await setup();
    try {
      // A code minted before the authorize endpoint required a challenge: nothing to
      // bind, so no verifier can redeem it.
      const code = 'dcr_pkce_required_legacy-code';
      await storeAuthCode(store, code, clientId, redirectUri);

      const response = await fetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: 'any-verifier',
        }),
      });

      assert.strictEqual(response.status, 400, 'a code without a challenge has no proof binding and is not redeemable');
      const payload = (await response.json()) as { error?: string };
      assert.strictEqual(payload.error, 'invalid_grant');
    } finally {
      server.close();
    }
  });

  it('redeems a code with the matching code_verifier', async () => {
    const { baseUrl, store, clientId, clientSecret, redirectUri, server } = await setup();
    try {
      const code = 'dcr_pkce_required_good-code';
      const verifier = 'dcr-test-code-verifier';
      await storeAuthCode(store, code, clientId, redirectUri, s256(verifier), 'S256');

      const response = await fetch(`${baseUrl}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });

      assert.strictEqual(response.status, 200, 'the verifier that minted the challenge must still redeem');
      const payload = (await response.json()) as { access_token?: string };
      assert.ok(payload.access_token, 'a redeemed code must return an access token');
    } finally {
      server.close();
    }
  });
});

describe('unit/dcr-router-iss', () => {
  const setup = async () => {
    const port = await getPort();
    const baseUrl = `http://localhost:${port}`;
    const app = express();
    const store = new Keyv();

    // An issuer distinct from baseUrl: iss must echo the advertised issuer, not the
    // base the endpoints happen to be served from.
    const issuerUrl = `${baseUrl}/as`;

    const dcrRouter = createDcrRouter({
      store,
      issuerUrl,
      baseUrl,
      scopesSupported: ['openid'],
      clientConfig: { clientId: 'test-ms-client-id' },
    });
    app.use('/', dcrRouter);

    const clientId = 'dcr_iss-client';
    const redirectUri = 'http://localhost:9999/callback';
    await store.set(`dcr:client:${clientId}`, {
      client_id: clientId,
      redirect_uris: [redirectUri],
      client_name: 'Iss Test Client',
    });

    return { baseUrl, issuerUrl, store, clientId, redirectUri, server: app.listen(port) };
  };

  it('advertises authorization_response_iss_parameter_supported in authorization server metadata', async () => {
    const { baseUrl, server } = await setup();
    try {
      const response = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
      const metadata = (await response.json()) as { authorization_response_iss_parameter_supported?: boolean };

      assert.strictEqual(metadata.authorization_response_iss_parameter_supported, true, 'the flag must be advertised, and only together with an emitted iss');
    } finally {
      server.close();
    }
  });

  it('carries iss on the authorization response redirect', async () => {
    const { baseUrl, issuerUrl, store, clientId, redirectUri, server } = await setup();
    try {
      // The callback handler exchanges the provider code before it redirects, so the
      // provider token endpoint is stubbed to keep this a local test with no provider call.
      const realFetch = globalThis.fetch;
      globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
        const url = input instanceof URL ? input.toString() : typeof input === 'string' ? input : input.url;
        if (url === 'https://login.microsoftonline.com/common/oauth2/v2.0/token') {
          return new Response(JSON.stringify({ access_token: 'ms-access-token', refresh_token: 'ms-refresh-token', expires_in: 3600, scope: 'openid' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return realFetch(input, init);
      }) as typeof fetch;

      try {
        const clientState = 'client-state';
        await store.set('dcr:ms-state:dcr-iss-test-state', {
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: 'openid',
          state: clientState,
          code_challenge: 'test-challenge',
          code_challenge_method: 'S256',
          created_at: Date.now(),
          expires_at: Date.now() + 600000,
        });

        const response = await fetch(`${baseUrl}/oauth/callback?code=ms-auth-code&state=dcr-iss-test-state`, { redirect: 'manual' });

        assert.strictEqual(response.status, 302, 'a successful provider exchange must redirect back to the client');
        const location = response.headers.get('location');
        assert.ok(location, 'the redirect must carry a Location header');

        const redirect = new URL(location);
        assert.ok(redirect.searchParams.get('code'), 'the redirect must still carry the authorization code');
        assert.strictEqual(redirect.searchParams.get('iss'), issuerUrl, 'iss must be the issuer the metadata advertises, not baseUrl');
        assert.strictEqual(redirect.searchParams.get('state'), clientState);
      } finally {
        globalThis.fetch = realFetch;
      }
    } finally {
      server.close();
    }
  });
});
