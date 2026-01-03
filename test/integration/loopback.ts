import '../lib/env-loader.ts';

/**
 * LoopbackOAuthProvider Integration Tests (Microsoft)
 *
 * Tests complete LoopbackOAuthProvider functionality including:
 * - Real Microsoft Graph API integration (User, Mail, OneDrive)
 * - Auth middleware and context injection
 * - Error handling and edge cases
 *
 * Requires valid test OAuth tokens (run npm run test:setup first).
 */

import type { ToolModule } from '@mcp-z/oauth';
import { Client } from '@microsoft/microsoft-graph-client';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { LoopbackOAuthProvider } from '../../src/index.ts';
import { MS_SCOPE } from '../constants.ts';
import { createConfig } from '../lib/config.ts';
import { logger } from '../lib/test-utils.ts';

const config = createConfig();

// Use isolated test token directory
// Run `npm run test:setup` first to generate tokens
const tokenStorePath = path.join(process.cwd(), '.tokens/test');

describe('LoopbackOAuthProvider Integration Tests (Microsoft)', () => {
  let testAccountId: string;
  let authProvider: LoopbackOAuthProvider;
  let middleware: ReturnType<typeof authProvider.authMiddleware>;

  before(async () => {
    // Create token store
    const tokenStore = new Keyv({
      store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
    });

    // Create auth provider
    authProvider = new LoopbackOAuthProvider({
      service: 'outlook',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: 'User.Read Mail.Read',
      headless: true,
      logger,
      tokenStore,
      tenantId: config.tenantId,
    });

    // Get test account ID from provider (requires valid token from test:setup)
    testAccountId = await authProvider.getUserEmail();

    // Setup middleware
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

  describe('Real Microsoft Graph API Integration', () => {
    it('should work with Microsoft Graph User API using toAuthProvider()', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'outlook',
        clientId: config.clientId,
        clientSecret: config.clientSecret || undefined,
        tenantId: config.tenantId,
        scope: MS_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const authProvider = auth.toAuthProvider(); // Use active account (set by test:setup)
      const graphClient = Client.initWithMiddleware({
        authProvider,
      });

      // Make a real API call to get user profile
      const user = await graphClient.api('/me').get();

      assert.ok(user, 'Should get user data');
      assert.ok(user.mail || user.userPrincipalName, 'Should have email address');
      assert.ok(user.displayName, 'Should have display name');
    });

    it('should work with Microsoft Graph Mail API using toAuthProvider()', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'outlook', // Reuse outlook token (same scopes)
        clientId: config.clientId,
        clientSecret: config.clientSecret || undefined,
        tenantId: config.tenantId,
        scope: MS_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const authProvider = auth.toAuthProvider(); // Use active account (set by test:setup)
      const graphClient = Client.initWithMiddleware({
        authProvider,
      });

      // Make a real API call to list mail folders
      const folders = await graphClient.api('/me/mailFolders').get();

      assert.ok(folders, 'Should get mail folders');
      assert.ok(Array.isArray(folders.value), 'Should have folders array');
      assert.ok(folders.value.length > 0, 'Should have at least one folder (Inbox)');
    });

    // OneDrive test skipped - requires Files.ReadWrite scope which may not be in test token
    // To enable: add Files.ReadWrite to test setup scopes and uncomment this test
    /*
    it('should work with Microsoft Graph OneDrive API using toAuthProvider()', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'outlook', // Reuse outlook token (same scopes)
        clientId: config.clientId,
        clientSecret: config.clientSecret || undefined,
        tenantId: config.tenantId,
        scope: MS_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const authProvider = auth.toAuthProvider(); // Use active account (set by test:setup)
      const graphClient = Client.initWithMiddleware({
        authProvider,
      });

      // Make a real API call to get OneDrive root
      const drive = await graphClient.api('/me/drive').get();

      assert.ok(drive, 'Should get drive data');
      assert.ok(drive.id, 'Should have drive ID');
      assert.ok(drive.driveType, 'Should have drive type');

      // List root folder contents
      const root = await graphClient.api('/me/drive/root/children').get();

      assert.ok(root, 'Should get root children');
      assert.ok(Array.isArray(root.value), 'Should have files/folders array');
    });
    */
  });

  describe('Middleware and Auth Context', () => {
    describe('Middleware Creation', () => {
      it('should create authMiddleware() wrapper', () => {
        // If authMiddleware() didn't throw, creation succeeded
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

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

        // Call handler (no _meta.accountId provided)
        await wrappedHandler({}, {});

        // Verify fixed account was used
        assert.strictEqual(capturedAccountId, testAccountId, 'Should use fixed account');
      });

      it('should use fixed account for real Microsoft Graph API calls', async () => {
        // Test tool handler that makes real API call
        let userEmail: string | undefined;
        const testHandler = async (_args: unknown, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => {
          const auth = (
            extra as {
              authContext?: { auth?: { getAccessToken: () => Promise<string> } };
            }
          ).authContext?.auth;
          assert.ok(auth, 'Auth should be defined');

          // Use Microsoft Graph API to get user email (real API call)
          const response = await fetch('https://graph.microsoft.com/v1.0/me', {
            headers: {
              Authorization: `Bearer ${await auth.getAccessToken()}`,
            },
          });
          const data = (await response.json()) as {
            mail?: string;
            userPrincipalName?: string;
          };
          userEmail = data.mail || data.userPrincipalName;

          return { content: [] };
        };

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'get user email', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

        // Call handler
        await wrappedHandler({}, {});

        // Verify API call succeeded
        assert.ok(userEmail, 'Should return user email from API');
        assert.ok(userEmail.includes('@'), 'Email should contain @ symbol');
      });

      it('should consistently use same account across multiple calls', async () => {
        const capturedAccounts: string[] = [];

        const testHandler = async (_args: unknown, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => {
          const accountId = (extra as { authContext?: { accountId?: string } }).authContext?.accountId;
          assert.ok(accountId, 'Account ID should be defined');
          capturedAccounts.push(accountId);
          return { content: [] };
        };

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

        // Make 5 concurrent calls
        await Promise.all(Array.from({ length: 5 }, () => wrappedHandler({}, {})));

        // Verify all calls used same account
        assert.equal(capturedAccounts.length, 5, 'Should have 5 results');
        const uniqueAccounts = new Set(capturedAccounts);
        assert.equal(uniqueAccounts.size, 1, 'All calls should use same account');
        assert.strictEqual(capturedAccounts[0], testAccountId, 'Should use fixed account');
      });
    });

    describe('Backchannel Override Support', () => {
      // NOTE: In the new API, authMiddleware() SUPPORTS backchannel overrides
      // This matches multipleUserMiddleware() for consistency and simplicity

      it('should support account override via _meta.accountId', async () => {
        let capturedAccountId: string | undefined;
        const testHandler = async (_args: unknown, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => {
          capturedAccountId = (extra as { authContext?: { accountId?: string } }).authContext?.accountId;
          return { content: [] };
        };

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

        // Override with testAccountId (which has a token)
        await wrappedHandler({}, { _meta: { accountId: testAccountId } });

        // Verify override was applied
        assert.strictEqual(capturedAccountId, testAccountId, 'Should use override account');
      });

      it('should prioritize override over active account', async () => {
        const capturedAccounts: string[] = [];
        const testHandler = async (_args: unknown, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => {
          const accountId = (extra as { authContext?: { accountId?: string } }).authContext?.accountId;
          assert.ok(accountId, 'Account ID should be defined');
          capturedAccounts.push(accountId);
          return { content: [] };
        };

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema) as (args: unknown, extra: unknown) => Promise<{ content: unknown[] }>;

        // Call with override (should use override, not active account)
        await Promise.all([wrappedHandler({}, { _meta: { accountId: testAccountId } }), wrappedHandler({}, { _meta: { accountId: testAccountId } }), wrappedHandler({}, { _meta: { accountId: testAccountId } })]);

        // Verify all overrides were applied
        assert.equal(capturedAccounts.length, 3, 'Should have 3 results');
        assert.ok(
          capturedAccounts.every((id) => id === testAccountId),
          'All should use override account'
        );
      });
    });

    describe('Error Handling', () => {
      it('should handle token not found for fixed account', async () => {
        // Create auth provider with empty token store (no accounts)
        const tokenStore = new Keyv(); // In-memory empty store

        const invalidAuthProvider = new LoopbackOAuthProvider({
          service: 'outlook',
          clientId: config.clientId,
          clientSecret: config.clientSecret || undefined,
          scope: 'User.Read Mail.Read',
          headless: true, // Don't open browser
          logger,
          tokenStore,
          tenantId: config.tenantId,
        });

        // Create middleware for non-existent account
        const invalidWithAuth = invalidAuthProvider.authMiddleware();

        const testHandler = async (_args: unknown, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => {
          // Trigger API call to force token lookup (which will throw AuthRequiredError)
          const auth = (
            extra as {
              authContext?: { auth?: { getAccessToken: () => Promise<string> } };
            }
          ).authContext?.auth;
          await fetch('https://graph.microsoft.com/v1.0/me', {
            headers: {
              Authorization: `Bearer ${await auth?.getAccessToken()}`,
            },
          });

          return { content: [] };
        };

        // Minimal test output schema (minimal for test)
        const testSchema = { result: {} };

        // Wrap handler with auth middleware
        // Uses double assertion because test tools use minimal mock schemas
        const toolModule = {
          name: 'test operation',
          config: { outputSchema: testSchema },
          handler: testHandler,
        } as unknown as ToolModule;
        const enhancedToolModule = invalidWithAuth.withToolAuth(toolModule);
        const wrappedHandler = enhancedToolModule.handler as (args: unknown, extra: unknown) => Promise<{ structuredContent?: { result?: { type?: string } } }>;

        // Middleware catches AuthRequiredError and returns auth_required response
        const result = await wrappedHandler({}, {});

        // Check for auth_required response in structuredContent
        assert.ok(result.structuredContent, 'Should return structuredContent');
        assert.strictEqual(result.structuredContent.result?.type, 'auth_required', 'Should return auth_required response when token not found');
      });
    });
  });
});
