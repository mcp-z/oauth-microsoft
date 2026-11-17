#!/usr/bin/env node

/**
 * DCR Token Setup Helper for Microsoft OAuth
 *
 * Runs a one-time DCR OAuth flow with browser interaction and stores
 * the provider refresh tokens for automated testing.
 *
 * Usage:
 *   Called by setup-token.ts
 */

import { randomUUID } from 'node:crypto';
import { DynamicClientRegistrar, isLoopbackUrl, OAuthCallbackListener, probeAuthCapabilities } from '@mcp-z/client';
import { generatePKCE, openUrl } from '@mcp-z/oauth';
import getPort from 'get-port';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import type { Logger } from '../../src/types.ts';
import { startDcrTestServer } from './servers/dcr-test-server.ts';

const TEST_PORT = 3456;
const BASE_URL = `http://localhost:${TEST_PORT}`;

interface SetupDcrTokenOptions {
  clientId: string;
  clientSecret?: string;
  tenantId?: string;
  scope: string;
  logger?: Logger;
}

interface DcrTokenData {
  clientId: string;
  clientSecret: string;
  providerRefreshToken: string;
  providerAccessToken: string;
  providerExpiresAt: number;
}

export function createDcrAuthorizationUrl(args: { authorizationEndpoint: string; clientId: string; redirectUri: string; scope: string; state: string; codeChallenge: string }): URL {
  const url = new URL(args.authorizationEndpoint);
  url.searchParams.set('client_id', args.clientId);
  url.searchParams.set('redirect_uri', args.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', args.scope);
  url.searchParams.set('state', args.state);
  url.searchParams.set('code_challenge', args.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url;
}

export function createDcrTokenBody(args: { code: string; redirectUri: string; clientId: string; clientSecret?: string; codeVerifier: string }): URLSearchParams {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: args.code,
    redirect_uri: args.redirectUri,
    client_id: args.clientId,
    code_verifier: args.codeVerifier,
  });
  if (args.clientSecret) body.set('client_secret', args.clientSecret);
  return body;
}

export function assertDcrCallbackState(actual: string | undefined, expected: string): void {
  if (!actual || actual !== expected) throw new Error('OAuth callback state mismatch');
}

export async function setupDcrToken(options: SetupDcrTokenOptions): Promise<void> {
  const { clientId, clientSecret, tenantId, scope } = options;

  console.log('Starting DCR OAuth flow for token acquisition...');
  console.log('');

  let dcrCleanup: (() => Promise<void>) | undefined;
  let callbackListener: OAuthCallbackListener | undefined;

  try {
    // Start DCR test server
    console.log('🔧 Starting temporary DCR server...');
    const serverResult = await startDcrTestServer({
      port: TEST_PORT,
      baseUrl: BASE_URL,
      scopes: [scope],
      clientId,
      ...(clientSecret && { clientSecret }),
      ...(tenantId && { tenantId }),
    });
    dcrCleanup = serverResult.close;
    console.log(`✅ DCR server running at ${serverResult.url}`);

    // Start callback listener
    console.log('\n📡 Starting callback server...');
    const callbackPort = await getPort({ host: 'localhost' });
    callbackListener = new OAuthCallbackListener({ port: callbackPort });
    await callbackListener.start();
    const callbackUrl = callbackListener.getCallbackUrl();
    console.log(`   Listening on ${callbackUrl}`);

    // Discover OAuth metadata
    console.log('\n🔍 Discovering OAuth metadata...');
    const capabilities = await probeAuthCapabilities(BASE_URL);
    if (!capabilities.registrationEndpoint || !capabilities.authorizationEndpoint || !capabilities.tokenEndpoint) {
      throw new Error('Missing required OAuth endpoints');
    }

    // Register client via DCR
    console.log('\n📝 Registering test client via DCR...');
    const registrar = new DynamicClientRegistrar();
    const registration = await registrar.registerClient(capabilities.registrationEndpoint, {
      clientName: 'DCR Test Setup (Microsoft)',
      redirectUri: callbackUrl,
      // The registrar refuses http:// unless the caller grants loopback trust. Grant it
      // from the URL this script configured, never from discovery data (SSRF mitigation).
      allowLoopback: isLoopbackUrl(BASE_URL),
    });
    console.log(`   Client ID: ${registration.clientId}`);

    // Bind the authorization request to this process and its later token exchange.
    const { verifier: codeVerifier, challenge: codeChallenge } = generatePKCE();
    const state = randomUUID();

    console.log('\n🔐 Initiating OAuth authorization...');
    const authUrl = createDcrAuthorizationUrl({
      authorizationEndpoint: capabilities.authorizationEndpoint,
      clientId: registration.clientId,
      redirectUri: callbackUrl,
      scope,
      state,
      codeChallenge,
    });
    console.log(`   Authorization URL: ${authUrl.toString()}`);

    // Begin waiting before the browser can deliver a fast callback. Promise.all
    // also attaches rejection handlers to both operations immediately.
    console.log('\n📋 Please authorize in your browser...');
    console.log('⏳ Waiting for authorization callback...');
    const [callback] = await Promise.all([callbackListener.waitForCallback(), openUrl(authUrl.toString())]);
    assertDcrCallbackState(callback.state, state);
    const { code } = callback;
    console.log('✅ Authorization code received');

    // Close callback server
    await callbackListener.stop();
    callbackListener = undefined;

    // Exchange code for access token
    console.log('\n🔄 Exchanging authorization code for tokens...');
    const response = await fetch(capabilities.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: createDcrTokenBody({
        code,
        redirectUri: callbackUrl,
        clientId: registration.clientId,
        clientSecret: registration.clientSecret,
        codeVerifier,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status}`);
    }

    const tokenData = (await response.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };

    const tokens = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: Date.now() + tokenData.expires_in * 1000,
    };

    if (!tokens.refreshToken) {
      throw new Error('No refresh token received - ensure offline_access is requested');
    }

    console.log('✅ Tokens received');

    // Verify provider tokens work by calling verify endpoint
    console.log('\n🔍 Verifying provider tokens...');
    const verifyResponse = await fetch(`${BASE_URL}/oauth/verify`, {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });

    if (!verifyResponse.ok) {
      throw new Error(`Verify endpoint failed: ${verifyResponse.status}`);
    }

    const verifyData = (await verifyResponse.json()) as {
      providerTokens: { accessToken: string; refreshToken?: string; expiresAt?: number };
    };

    console.log('✅ Provider tokens verified');

    // Store DCR tokens
    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({
      store: new KeyvFile({ filename: dcrTokenPath }),
    });

    const dcrTokenData: DcrTokenData = {
      clientId: registration.clientId,
      clientSecret: registration.clientSecret ?? '',
      providerRefreshToken: verifyData.providerTokens.refreshToken ?? tokens.refreshToken,
      providerAccessToken: verifyData.providerTokens.accessToken,
      providerExpiresAt: verifyData.providerTokens.expiresAt ?? Date.now() + 3600 * 1000,
    };

    await dcrStore.set('microsoft', dcrTokenData);
    console.log(`✅ DCR tokens saved to: ${dcrTokenPath}`);

    // Cleanup
    if (dcrCleanup) {
      await dcrCleanup();
      dcrCleanup = undefined;
    }

    console.log('\n✅ DCR token setup completed successfully!');
  } catch (error) {
    console.error('\n❌ DCR token setup failed:', error instanceof Error ? error.message : String(error));
    throw error;
  } finally {
    // Cleanup resources
    if (callbackListener) {
      await callbackListener.stop();
    }
    if (dcrCleanup) {
      await dcrCleanup();
    }
  }
}
