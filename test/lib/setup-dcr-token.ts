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

import { DynamicClientRegistrar, OAuthCallbackListener, probeAuthCapabilities } from '@mcp-z/client';
import getPort from 'get-port';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import open from 'open';
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
    const callbackPort = await getPort();
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
    });
    console.log(`   Client ID: ${registration.clientId}`);

    // Build authorization URL
    console.log('\n🔐 Initiating OAuth authorization...');
    const authUrl = new URL(capabilities.authorizationEndpoint);
    authUrl.searchParams.set('client_id', registration.clientId);
    authUrl.searchParams.set('redirect_uri', callbackUrl);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', scope);
    console.log(`   Authorization URL: ${authUrl.toString()}`);

    // Open browser for user authorization
    console.log('\n📋 Please authorize in your browser...');
    await open(authUrl.toString());

    // Wait for callback
    console.log('⏳ Waiting for authorization callback...');
    const { code } = await callbackListener.waitForCallback();
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
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: callbackUrl,
        client_id: registration.clientId,
        client_secret: registration.clientSecret,
      }).toString(),
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
    console.log(`   Access Token: ${tokens.accessToken.substring(0, 20)}...`);
    console.log(`   Refresh Token: ${tokens.refreshToken.substring(0, 20)}...`);

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
