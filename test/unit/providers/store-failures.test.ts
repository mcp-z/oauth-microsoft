import '../../lib/env-loader.ts';
import { setToken } from '@mcp-z/oauth';
import { createLoopbackCallbackRouter, DeviceCodeProvider, LoopbackOAuthProvider } from '@mcp-z/oauth-microsoft';
import assert from 'assert';
import express from 'express';
import type { Server } from 'http';
import { createServer, request as httpRequest } from 'http';
import type { AddressInfo } from 'net';
import { createFailingStore } from '../../lib/failing-store.ts';
import { redirectFetch } from '../../lib/redirect-fetch.ts';
import { logger } from '../../lib/test-utils.ts';

const base = { service: 'outlook' as const, clientId: 'test-client', tenantId: 'common', scope: 'User.Read', headless: false };

type Waiting = { waitForOAuthCompletion(state: string): Promise<unknown> };

function waitOn(provider: LoopbackOAuthProvider, state: string) {
  const outcome: { settled: boolean; value?: unknown; error?: unknown } = { settled: false };
  (provider as unknown as Waiting).waitForOAuthCompletion(state).then(
    (value) => Object.assign(outcome, { settled: true, value }),
    (error: unknown) => Object.assign(outcome, { settled: true, error })
  );
  return outcome;
}

// The callback response is fully read before this runs, so a waiter that was told about the failure has settled;
// one that was not is still polling (it would give up only after 5 minutes).
function assertRejected(outcome: { settled: boolean; error?: unknown }, message: RegExp) {
  assert.ok(outcome.settled, 'the waiting call must be rejected once the callback has failed');
  assert.ok(outcome.error instanceof Error, 'the waiting call must reject with an Error');
  assert.match((outcome.error as Error).message, message);
}

describe('unit/provider-store-failures', () => {
  // The abandoned-sign-in timer calls this with `void`; a rejection there was an unhandled rejection that ends the process.
  it('loopback: discardAbandonedPendingAuth resolves and logs a warning when the store delete fails', async () => {
    const { store, fail } = createFailingStore();
    fail();
    const warnings: unknown[][] = [];
    const provider = new LoopbackOAuthProvider({ ...base, logger: { ...logger, warn: (...args: unknown[]) => void warnings.push(args) }, tokenStore: store });

    await (provider as unknown as { discardAbandonedPendingAuth(stateId: string): Promise<void> }).discardAbandonedPendingAuth('state-1');

    assert.strictEqual(warnings.length, 1);
    assert.match(String(warnings[0]?.[0]), /abandoned pending OAuth state/);
  });

  describe('refresh then save', () => {
    let tokenServer: Server;
    let restoreFetch: () => void;

    before(async () => {
      // Controlled token endpoint answering a successful refresh (RFC 6749 section 5.1).
      tokenServer = createServer((_req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ access_token: 'fresh-access', expires_in: 3600, token_type: 'Bearer' }));
      });
      await new Promise<void>((resolve) => tokenServer.listen(0, '127.0.0.1', resolve));
      restoreFetch = redirectFetch('login.microsoftonline.com', `http://127.0.0.1:${(tokenServer.address() as AddressInfo).port}`);
    });

    after(() => {
      restoreFetch();
      tokenServer.close();
    });

    // A save that fails after a good refresh used to be reported as a failed refresh;
    // the storage error must come out as itself.
    for (const [name, make] of [
      ['loopback', (config: ConstructorParameters<typeof LoopbackOAuthProvider>[0]) => new LoopbackOAuthProvider(config)],
      ['device-code', (config: ConstructorParameters<typeof LoopbackOAuthProvider>[0]) => new DeviceCodeProvider(config)],
    ] as const) {
      it(`${name}: surfaces a storage failure as itself, not as a failed refresh`, async () => {
        const { store, fail } = createFailingStore();
        const infos: string[] = [];
        await setToken(store, { accountId: 'a@example.com', service: 'outlook' }, { accessToken: 'old', refreshToken: 'r', expiresAt: Date.now() - 1000 });
        fail();
        const provider = make({ ...base, logger: { ...logger, info: (message: unknown) => void infos.push(String(message)) }, tokenStore: store });

        await assert.rejects(provider.getAccessToken('a@example.com'), /store write failed/);
        assert.ok(!infos.some((message) => message.includes('Token refresh failed')), 'must not be reported as a refresh failure');
      });
    }
  });
  describe('failed loopback callback', () => {
    let tokenServer: Server;
    let restoreToken: () => void;
    let restoreGraph: () => void;
    let tokenAnswer: { status: number; body: string };

    before(async () => {
      // Controlled provider: token endpoint (RFC 6749 sections 5.1/5.2) and the Graph profile endpoint.
      tokenServer = createServer((req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.url?.startsWith('/v1.0/me')) {
          res.end(JSON.stringify({ mail: 'a@example.com' }));
          return;
        }
        res.statusCode = tokenAnswer.status;
        res.end(tokenAnswer.body);
      });
      await new Promise<void>((resolve) => tokenServer.listen(0, '127.0.0.1', resolve));
      const origin = `http://127.0.0.1:${(tokenServer.address() as AddressInfo).port}`;
      restoreToken = redirectFetch('login.microsoftonline.com', origin);
      restoreGraph = redirectFetch('graph.microsoft.com', origin);
    });

    after(() => {
      restoreGraph();
      restoreToken();
      tokenServer.close();
    });

    beforeEach(() => {
      tokenAnswer = { status: 200, body: JSON.stringify({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600, token_type: 'Bearer' }) };
    });

    // Starts a real sign-in and waits on it the way the middleware does, without opening a browser.
    async function startSignIn(provider: LoopbackOAuthProvider) {
      let descriptorUrl = '';
      await provider.getAccessToken().catch((error: unknown) => {
        descriptorUrl = (error as { descriptor: { url: string } }).descriptor.url;
      });
      const authUrl = new URL(descriptorUrl);
      const state = authUrl.searchParams.get('state') as string;
      const callback = new URL(authUrl.searchParams.get('redirect_uri') as string);
      callback.searchParams.set('state', state);
      return { callback, state, outcome: waitOn(provider, state) };
    }

    it('rejects the waiting call with the storage error when saving the token fails', async () => {
      const { store, fail } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);
      callback.searchParams.set('code', 'good-code');
      fail();

      const response = await fetch(callback);
      const page = await response.text();

      assert.strictEqual(response.status, 500);
      assert.ok(!page.includes('Authentication successful'), 'the tab must not show success');
      assertRejected(outcome, /store write failed/);
    });

    it('rejects the waiting call with the provider error when consent is cancelled', async () => {
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);
      callback.searchParams.set('error', 'access_denied');
      callback.searchParams.set('error_description', 'The user denied access');

      const response = await fetch(callback);
      await response.text();

      assert.strictEqual(response.status, 400);
      assertRejected(outcome, /access_denied.*The user denied access/);
    });

    it('rejects the waiting call when the callback carries no code', async () => {
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);

      const response = await fetch(callback);
      await response.text();

      assert.strictEqual(response.status, 400);
      assertRejected(outcome, /No authorization code received/);
    });

    it('rejects the waiting call with the provider answer when the code exchange fails', async () => {
      tokenAnswer = { status: 400, body: JSON.stringify({ error: 'invalid_grant', error_description: 'Bad Request' }) };
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);
      callback.searchParams.set('code', 'rejected-code');

      const response = await fetch(callback);
      const page = await response.text();

      assert.strictEqual(response.status, 500);
      assert.ok(!page.includes('Authentication successful'), 'the tab must not show success');
      assertRejected(outcome, /Token exchange failed: 400.*invalid_grant/);
      assert.ok(!(outcome.error as Error).message.includes('rejected-code'), 'the code must not appear in the message');
    });

    it('rejects the waiting call when the callback has no state', async () => {
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);
      callback.searchParams.delete('state');
      callback.searchParams.set('code', 'some-code');

      const response = await fetch(callback);
      await response.text();

      assert.strictEqual(response.status, 400);
      assertRejected(outcome, /Missing state parameter/);
    });

    it('rejects the waiting call, once and without a stale entry, when the callback state is not the flow state', async () => {
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);
      callback.searchParams.set('state', 'some-other-state');
      callback.searchParams.set('code', 'some-code');

      const response = await fetch(callback);
      await response.text();

      assert.strictEqual(response.status, 500);
      assertRejected(outcome, /Invalid or expired OAuth state/);
      assert.strictEqual((provider as unknown as { callbackFailures: Map<string, Error> }).callbackFailures.size, 0, 'the failure is consumed by the waiter');
    });

    it('rejects the waiting call when the callback request cannot be parsed', async () => {
      const { store } = createFailingStore();
      const provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: store });
      const { callback, outcome } = await startSignIn(provider);

      // `//` is not a URL once resolved against the loopback base.
      const status = await new Promise<number>((resolve, reject) => {
        const request = httpRequest({ host: callback.hostname, port: callback.port, path: '//' }, (response) => {
          response.resume();
          response.on('end', () => resolve(response.statusCode as number));
        });
        request.on('error', reject);
        request.end();
      });

      assert.strictEqual(status, 500);
      assertRejected(outcome, /Invalid URL/);
    });
  });

  describe('failed persistent callback', () => {
    let tokenServer: Server;
    let callbackServer: Server;
    let callbackBase: string;
    let restoreToken: () => void;
    let restoreGraph: () => void;
    let tokenAnswer: { status: number; body: string };
    let provider: LoopbackOAuthProvider;
    let fail: () => void;

    before(async () => {
      tokenServer = createServer((req, res) => {
        res.setHeader('Content-Type', 'application/json');
        if (req.url?.startsWith('/v1.0/me')) {
          res.end(JSON.stringify({ mail: 'a@example.com' }));
          return;
        }
        res.statusCode = tokenAnswer.status;
        res.end(tokenAnswer.body);
      });
      await new Promise<void>((resolve) => tokenServer.listen(0, '127.0.0.1', resolve));
      const origin = `http://127.0.0.1:${(tokenServer.address() as AddressInfo).port}`;
      restoreToken = redirectFetch('login.microsoftonline.com', origin);
      restoreGraph = redirectFetch('graph.microsoft.com', origin);
    });

    after(() => {
      restoreGraph();
      restoreToken();
      tokenServer.close();
    });

    beforeEach(async () => {
      tokenAnswer = { status: 200, body: JSON.stringify({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600, token_type: 'Bearer' }) };
      const failing = createFailingStore();
      fail = failing.fail;
      provider = new LoopbackOAuthProvider({ ...base, logger, tokenStore: failing.store, redirectUri: 'https://example.com/oauth/callback' });
      const app = express();
      app.use(createLoopbackCallbackRouter(provider));
      callbackServer = app.listen(0, '127.0.0.1');
      await new Promise<void>((resolve) => callbackServer.once('listening', resolve));
      callbackBase = `http://127.0.0.1:${(callbackServer.address() as AddressInfo).port}`;
    });

    afterEach(() => {
      callbackServer.close();
    });

    async function startPersistentSignIn() {
      let descriptorUrl = '';
      await provider.getAccessToken().catch((error: unknown) => {
        descriptorUrl = (error as { descriptor: { url: string } }).descriptor.url;
      });
      const state = new URL(descriptorUrl).searchParams.get('state') as string;
      return { state, outcome: waitOn(provider, state) };
    }

    it('rejects the waiting call with the storage error when saving the token fails', async () => {
      const { state, outcome } = await startPersistentSignIn();
      fail();

      const response = await fetch(`${callbackBase}/oauth/callback?code=good-code&state=${state}`);
      await response.text();

      assert.strictEqual(response.status, 500);
      assertRejected(outcome, /store write failed/);
    });

    // A reload or duplicate callback after a completed sign-in is answered invalid_grant by the provider (code already used).
    it('resolves the waiting call when a second callback for a completed sign-in fails', async () => {
      const { state, outcome } = await startPersistentSignIn();
      const callback = `${callbackBase}/oauth/callback?code=used-once&state=${state}`;

      const first = await fetch(callback);
      await first.text();
      tokenAnswer = { status: 400, body: JSON.stringify({ error: 'invalid_grant', error_description: 'Bad Request' }) };
      const second = await fetch(callback);
      await second.text();

      assert.strictEqual(first.status, 200);
      assert.strictEqual(second.status, 500);
      assert.ok(outcome.settled, 'the failed duplicate callback must wake the waiter');
      assert.strictEqual(outcome.error, undefined, 'a completed sign-in must not be reported as failed');
      assert.deepStrictEqual(outcome.value, { email: 'a@example.com' });
    });

    it('rejects the waiting call with the provider answer when the code exchange fails', async () => {
      tokenAnswer = { status: 400, body: JSON.stringify({ error: 'invalid_grant', error_description: 'Bad Request' }) };
      const { state, outcome } = await startPersistentSignIn();

      const response = await fetch(`${callbackBase}/oauth/callback?code=rejected-code&state=${state}`);
      await response.text();

      assert.strictEqual(response.status, 500);
      assertRejected(outcome, /Token exchange failed: 400.*invalid_grant/);
      assert.ok(!(outcome.error as Error).message.includes('rejected-code'), 'the code must not appear in the message');
    });
  });
});
