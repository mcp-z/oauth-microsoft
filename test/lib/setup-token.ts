#!/usr/bin/env node

/**
 * Minimal OAuth token setup for oauth-microsoft library tests
 *
 * Generates BOTH loopback and device code tokens for comprehensive testing.
 * Self-contained test utility with minimal dependencies.
 *
 * Usage:
 *   npm run test:setup
 */

import { getToken } from '@mcp-z/oauth';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { DeviceCodeProvider } from '../../src/providers/device-code.ts';
import { LoopbackOAuthProvider } from '../../src/providers/loopback-oauth.ts';
import { createConfig } from '../../src/setup/config.ts';
import { MS_SCOPE } from '../constants.ts';
import { loadDcrTokens } from './dcr-token-helper.ts';
import { setupDcrToken } from './setup-dcr-token.ts';
import { logger } from './test-utils.ts';

const config = createConfig();

async function setupToken(): Promise<void> {
  console.log('🔐 Microsoft OAuth Test Token Setup');
  console.log('This script will generate tokens for loopback, device code, and DCR flows.');
  console.log('');

  // Use package-local .tokens/test directory
  const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');
  const tokenStore = new Keyv({
    store: new KeyvFile({ filename: tokenStorePath }),
  });

  // Step 1: Generate loopback token
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Step 1/3: Loopback OAuth Flow');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  const loopback = new LoopbackOAuthProvider({
    service: 'outlook',
    clientId: config.clientId,
    clientSecret: config.clientSecret || undefined,
    scope: MS_SCOPE,
    headless: false,
    logger,
    tokenStore,
    tenantId: config.tenantId,
  });

  console.log('Starting loopback OAuth flow...');
  console.log('');

  // Trigger OAuth flow via middleware (handles auth_url by opening browser + polling)
  const loopbackMiddleware = loopback.authMiddleware();
  const loopbackSetupTool = loopbackMiddleware.withToolAuth({
    name: 'test-setup-loopback',
    config: {},
    handler: async () => {
      return { ok: true };
    },
  });
  await (loopbackSetupTool.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});
  const loopbackEmail = await loopback.getUserEmail();

  console.log('');
  console.log('✅ Loopback token generated successfully!');
  console.log(`📧 Authenticated as: ${loopbackEmail}`);
  console.log(`🔑 Storage key: accountId='${loopbackEmail}', service='outlook'`);
  console.log('');

  // Step 2: Generate device code token
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Step 2/3: Device Code OAuth Flow');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  if (!config.tenantId) {
    throw new Error('MS_TENANT_ID environment variable is required for device code flow. Check .env.test');
  }

  const deviceCode = new DeviceCodeProvider({
    service: 'outlook',
    clientId: config.clientId,
    tenantId: config.tenantId,
    scope: MS_SCOPE,
    headless: false,
    logger: {
      info: console.log,
      error: console.error,
      warn: console.warn,
      debug: console.log,
    },
    tokenStore,
  });

  console.log('Checking for existing device code token...');
  console.log('');

  // Check storage directly to avoid triggering device code flow unnecessarily
  const existingDeviceToken = await getToken<{ accessToken: string; refreshToken?: string; expiresAt?: number; scope?: string }>(tokenStore, { accountId: 'device-code', service: 'outlook' });

  let deviceEmail: string;
  if (existingDeviceToken && existingDeviceToken.expiresAt && existingDeviceToken.expiresAt > Date.now()) {
    console.log('✅ Valid device code token already exists!');
    deviceEmail = await deviceCode.getUserEmail('device-code');
    console.log(`📧 Authenticated as: ${deviceEmail}`);
    console.log(`🔑 Storage key: accountId='device-code', service='outlook'`);
  } else {
    console.log('No valid device code token found. Starting device code flow...');
    console.log('');

    try {
      // Trigger OAuth flow via middleware (handles device code by polling for completion)
      const deviceCodeMiddleware = deviceCode.authMiddleware();
      const deviceCodeSetupTool = deviceCodeMiddleware.withToolAuth({
        name: 'test-setup-device-code',
        config: {},
        handler: async () => {
          return { ok: true };
        },
      });
      await (deviceCodeSetupTool.handler as (args: unknown, extra: unknown) => Promise<unknown>)({ accountId: 'device-code' }, {});
      deviceEmail = await deviceCode.getUserEmail('device-code');
    } catch (error) {
      console.error('Device code flow failed:', error);
      throw error;
    }

    console.log('');
    console.log('✅ Device code token generated successfully!');
    console.log(`📧 Authenticated as: ${deviceEmail}`);
    console.log(`🔑 Storage key: accountId='device-code', service='outlook'`);
  }

  console.log('');

  // Step 3: Generate DCR token
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Step 3/3: DCR OAuth Flow');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  // Get DCR-specific credentials from environment - completely separate from loopback config
  const dcrClientId = process.env.MS_TEST_DCR_CLIENT_ID;
  const dcrClientSecret = process.env.MS_TEST_DCR_CLIENT_SECRET;
  const dcrTenantId = process.env.MS_TEST_DCR_TENANT_ID;

  if (!dcrClientId || !dcrTenantId) {
    console.log('⚠️  Skipping DCR token setup - MS_TEST_DCR_CLIENT_ID or MS_TEST_DCR_TENANT_ID not set');
    console.log('   Set MS_TEST_DCR_CLIENT_ID, MS_TEST_DCR_CLIENT_SECRET, and MS_TEST_DCR_TENANT_ID in .env.test to enable DCR testing');
    console.log('');
  } else {
    // Check for existing DCR tokens
    let existingDcrToken = await loadDcrTokens();

    // Try to refresh if token exists but is expired
    if (existingDcrToken && existingDcrToken.providerExpiresAt <= Date.now()) {
      console.log('⚠️  Existing DCR token expired. Attempting to refresh...');
      console.log('');

      try {
        // Refresh the Microsoft access token using DCR tenant
        const tokenUrl = `https://login.microsoftonline.com/${dcrTenantId}/oauth2/v2.0/token`;
        const params: Record<string, string> = {
          refresh_token: existingDcrToken.providerRefreshToken,
          client_id: dcrClientId,
          grant_type: 'refresh_token',
        };
        if (dcrClientSecret) {
          params.client_secret = dcrClientSecret;
        }

        const response = await fetch(tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(params).toString(),
        });

        if (response.ok) {
          const tokenResponse = (await response.json()) as {
            access_token: string;
            expires_in?: number;
          };

          // Update stored token with refreshed access token
          const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
          const dcrStore = new Keyv({
            store: new KeyvFile({ filename: dcrTokenPath }),
          });

          existingDcrToken.providerAccessToken = tokenResponse.access_token;
          existingDcrToken.providerExpiresAt = Date.now() + (tokenResponse.expires_in ?? 3600) * 1000;

          await dcrStore.set('microsoft', existingDcrToken);

          console.log('✅ DCR token refreshed successfully!');
          console.log(`   Access Token: ${existingDcrToken.providerAccessToken.substring(0, 20)}...`);
          console.log('');
        } else {
          console.log('⚠️  Token refresh failed. Starting new OAuth flow...');
          console.log('');
          existingDcrToken = undefined; // Force new OAuth flow
        }
      } catch (error) {
        console.log('⚠️  Token refresh error:', error instanceof Error ? error.message : String(error));
        console.log('   Starting new OAuth flow...');
        console.log('');
        existingDcrToken = undefined; // Force new OAuth flow
      }
    }

    if (existingDcrToken && existingDcrToken.providerExpiresAt > Date.now()) {
      console.log('✅ Valid DCR token available!');
      console.log(`   Client ID: ${existingDcrToken.clientId}`);
      console.log(`   Access Token: ${existingDcrToken.providerAccessToken.substring(0, 20)}...`);
      console.log(`   Refresh Token: ${existingDcrToken.providerRefreshToken.substring(0, 20)}...`);
      console.log('');
    } else {
      // Import DCR setup helper

      const dcrOptions: Parameters<typeof setupDcrToken>[0] = {
        clientId: dcrClientId,
        scope: MS_SCOPE,
        logger,
      };
      if (dcrClientSecret) {
        dcrOptions.clientSecret = dcrClientSecret;
      }
      if (dcrTenantId) {
        dcrOptions.tenantId = dcrTenantId;
      }
      await setupDcrToken(dcrOptions);
    }
  }

  console.log('');

  // Final summary
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ All tokens generated successfully!');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  console.log(`📧 Loopback: ${loopbackEmail} (accountId='${loopbackEmail}')`);
  console.log(`📧 Device code: ${deviceEmail} (accountId='device-code')`);
  console.log(`📁 Loopback/Device tokens: ${tokenStorePath}`);
  console.log('📁 DCR tokens: .tokens/dcr.json');
  console.log('');
  console.log('Run `npm test` to verify Microsoft Graph integration');
  console.log('Run `npm run test:integration` to verify DCR flow');
}

// Run if executed directly
if (import.meta.main) {
  setupToken()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Token setup failed:', error.message);
      process.exit(1);
    });
}
