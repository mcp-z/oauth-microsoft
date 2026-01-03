/**
 * Device Code Single-User Context Integration Test (Microsoft)
 *
 * Tests DeviceCodeProvider with authMiddleware() and real Microsoft Graph API integration.
 * Uses cached tokens from test:setup - no new OAuth flows.
 *
 * Pattern:
 * 1. Create DeviceCodeProvider with cached token storage
 * 2. Use authMiddleware()
 * 3. Test real Microsoft Graph API calls with cached tokens
 * 4. Test token caching and middleware injection
 */

import type { ToolModule } from '@mcp-z/oauth';
import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { DeviceCodeProvider } from '../../src/index.ts';
import { MS_SCOPE } from '../constants.ts';
import { createConfig } from '../lib/config.ts';
import { logger } from '../lib/test-utils.ts';

const config = createConfig();

describe('Device Code Single-User Context Integration (Microsoft OAuth)', () => {
  let authProvider: DeviceCodeProvider;
  let middleware: ReturnType<typeof authProvider.authMiddleware>;

  before(async () => {
    // Use cached token store (tokens generated via npm run test:setup -- --auth=device-code)
    const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');
    const tokenStore = new Keyv({
      store: new KeyvFile({ filename: tokenStorePath }),
    });

    // Create device code provider
    authProvider = new DeviceCodeProvider({
      service: 'outlook',
      clientId: config.clientId,
      tenantId: config.tenantId || 'common',
      scope: MS_SCOPE,
      headless: true,
      logger,
      tokenStore,
    });

    // Setup single-user mode
    middleware = authProvider.authMiddleware();
  });

  // Helper to wrap handler with new ToolModule API
  // Uses double assertion because test tools use minimal mock schemas, not full Zod schemas
  function wrapHandlerWithAuth(handler: unknown, operation: string, schema: unknown) {
    const toolModule = {
      name: operation,
      config: { outputSchema: schema },
      handler,
    } as unknown as ToolModule;
    const enhancedToolModule = middleware.withToolAuth(toolModule);
    return enhancedToolModule.handler;
  }

  describe('Middleware Creation', () => {
    it('should create authMiddleware() wrapper', () => {
      assert.ok(middleware, 'Should create auth middleware wrapper');
    });
  });

  describe('Fixed Account Usage', () => {
    it('should use fixed account for auth context', async () => {
      // Test tool handler
      let capturedAccountId: string | undefined;
      const testHandler = async (_args: unknown, extra: unknown) => {
        capturedAccountId = (extra as { authContext?: { accountId?: string } }).authContext?.accountId;
        return { content: [] };
      };

      // Minimal test output schema
      const testSchema = { result: {} };

      // Wrap handler with auth middleware
      const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

      // Call handler
      await wrappedHandler({}, {});

      // Verify fixed account was used (device-code uses accountId='device-code')
      assert.strictEqual(capturedAccountId, 'device-code', 'Should use fixed accountId');
    });
  });

  describe('Microsoft Graph API Integration', () => {
    it('should successfully call Microsoft Graph /me endpoint', async () => {
      // Create test handler that calls Microsoft Graph API
      const testHandler = async (_args: unknown, extra: unknown) => {
        const authContext = (extra as { authContext?: { auth: { getAccessToken: () => Promise<string> } } }).authContext;
        assert.ok(authContext, 'Auth context should be injected');
        assert.ok(authContext.auth, 'Auth provider should be present');

        // Get access token and call Microsoft Graph
        const token = await authContext.auth.getAccessToken();
        assert.ok(token, 'Should get access token');

        const response = await fetch('https://graph.microsoft.com/v1.0/me', {
          headers: { Authorization: `Bearer ${token}` },
        });

        assert.ok(response.ok, 'Microsoft Graph API call should succeed');

        const userData = (await response.json()) as { userPrincipalName?: string; mail?: string };
        assert.ok(userData.userPrincipalName || userData.mail, 'Should return user email');

        return { content: [] };
      };

      const testSchema = { result: {} };
      const wrappedHandler = wrapHandlerWithAuth(testHandler, 'graph-me', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

      await wrappedHandler({}, {});
    });

    it('should cache and reuse access token', async () => {
      let tokenCallCount = 0;

      // Create test handler that tracks token calls
      const testHandler = async (_args: unknown, extra: unknown) => {
        const authContext = (extra as { authContext?: { auth: { getAccessToken: () => Promise<string> } } }).authContext;
        const token = await authContext?.auth.getAccessToken();
        tokenCallCount++;

        assert.ok(token, 'Should get access token');

        return { content: [] };
      };

      const testSchema = { result: {} };
      const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test-caching', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

      // Call handler multiple times
      await wrappedHandler({}, {});
      await wrappedHandler({}, {});
      await wrappedHandler({}, {});

      // All calls should use cached token (getAccessToken called 3 times, but device code flow only once)
      assert.strictEqual(tokenCallCount, 3, 'Should call getAccessToken 3 times');

      // Verify token is still valid by calling Microsoft Graph
      const token = await authProvider.getAccessToken();
      const response = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${token}` },
      });

      assert.ok(response.ok, 'Cached token should be valid for Microsoft Graph API');
    });
  });

  describe('getAccessToken()', () => {
    it('should return valid access token from cache', async () => {
      const token = await authProvider.getAccessToken();

      assert.ok(token, 'Token should be returned');
      assert.ok(token.length > 20, 'Token should be substantial length');
      assert.ok(typeof token === 'string', 'Token should be string');
    });

    it('should consistently return same cached token', async () => {
      const token1 = await authProvider.getAccessToken();
      const token2 = await authProvider.getAccessToken();

      assert.strictEqual(token1, token2, 'Should return consistent cached token');
    });
  });
});
