/**
 * LoopbackOAuthProvider Middleware Tests
 *
 * Tests for authMiddleware() behavior across different account scenarios.
 * Validates auth client creation, context injection, and account switching.
 *
 * Security Model: Loopback OAuth with server-managed token storage
 */

import { addAccount, type CachedToken, createAccountKey, removeAccount, setActiveAccount } from '@mcp-z/oauth';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import * as fs from 'fs';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { type EnrichedExtra, LoopbackOAuthProvider, type ToolModule } from '../../../src/index.ts';
import { createConfig } from '../../lib/config.ts';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

const config = createConfig();

let sharedTokenStore: Keyv;
let sharedAuthProvider: LoopbackOAuthProvider;
let realTokenData: CachedToken;

before(async () => {
  // Load real token from test setup
  const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');

  if (!fs.existsSync(tokenStorePath)) {
    throw new Error(`Token file not found at ${tokenStorePath}. Run \`npm run test:setup\` to generate OAuth token.`);
  }

  const testTokenStore = new Keyv({
    store: new KeyvFile({ filename: tokenStorePath }),
  });

  // Find test account (using createAccountKey format: {accountId}:outlook:token)
  const allKeys: string[] = [];
  const iterator = testTokenStore.iterator?.(undefined);
  if (iterator) {
    for await (const [key] of iterator) {
      allKeys.push(key);
    }
  }

  const outlookTokenKey = allKeys.find((k) => {
    const parts = k.replace(/^keyv:/, '').split(':');
    return parts.length === 3 && parts[1] === 'outlook' && parts[2] === 'token';
  });
  if (!outlookTokenKey) {
    throw new Error('No Outlook test token found. Run `npm run test:setup` to generate OAuth token.');
  }

  const tokenData = await testTokenStore.get(outlookTokenKey);
  if (!tokenData?.accessToken) {
    throw new Error('Token found but missing accessToken field. Run `npm run test:setup` to regenerate.');
  }
  realTokenData = tokenData;

  // Create shared token store for all tests (in-memory)
  sharedTokenStore = new Keyv();

  // Read scope from environment variable (set in .env.test)
  const msScope = process.env.MS_SCOPE;
  if (!msScope) {
    throw new Error('MS_SCOPE environment variable is required. Check .env.test');
  }

  // Create production LoopbackOAuthProvider
  sharedAuthProvider = new LoopbackOAuthProvider({
    service: 'outlook',
    clientId: config.clientId,
    clientSecret: config.clientSecret || undefined,
    tenantId: config.tenantId,
    scope: msScope,
    headless: true,
    logger,
    tokenStore: sharedTokenStore,
  });
});

// Clear token store before each test to ensure isolation
beforeEach(async () => {
  const iterator = sharedTokenStore.iterator?.(undefined);
  if (iterator) {
    for await (const [key] of iterator) {
      await sharedTokenStore.delete(key);
    }
  }
});

// Simple output schema for testing
const testOutputSchema = {
  result: {
    type: 'object',
    properties: {
      message: { type: 'string' },
    },
  },
} as const;

// ============================================================================
// Test Helpers
// ============================================================================

// Helper: Create unique userId for test isolation
function createTestUserId(): string {
  return `test-user-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// Helper: Setup test context with accounts
async function setupTestContext(accounts: string[]): Promise<{ userId: string; middleware: ReturnType<typeof sharedAuthProvider.authMiddleware> }> {
  const userId = createTestUserId();
  for (const account of accounts) {
    await sharedTokenStore.set(createAccountKey('token', { accountId: account, service: 'outlook' }), realTokenData);
    await addAccount(sharedTokenStore, { service: 'outlook', accountId: account });
  }
  return { userId, middleware: sharedAuthProvider.authMiddleware() };
}

// Helper: Create tool that captures extra fields
function createCapturingTool<T>(capture: (extra: EnrichedExtra) => T): { captured: T[]; toolModule: ToolModule } {
  const captured: T[] = [];
  const handler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
    captured.push(capture(extra));
    return { content: [{ type: 'text', text: 'success' }] };
  };
  return {
    captured,
    toolModule: { name: 'test-tool', config: { inputSchema: {}, outputSchema: testOutputSchema }, handler } as unknown as ToolModule,
  };
}

// Type alias for handler function
type Handler = (args: unknown, extra: unknown) => Promise<unknown>;
type AuthRequiredHandler = (args: unknown, extra: unknown) => Promise<{ structuredContent?: { result?: { type?: string } } }>;

// ============================================================================
// Basic Functionality Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Basic Functionality', () => {
  it('creates middleware wrapper function', async () => {
    // Setup token for test account
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'alice@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'alice@outlook.com',
    });

    // Create middleware - account selection based on userId
    const middleware = sharedAuthProvider.authMiddleware();

    // Verify middleware is an object with forTool/forResource/forPrompt methods
    assert.strictEqual(typeof middleware, 'object');
    assert.strictEqual(typeof middleware.withToolAuth, 'function');
    assert.strictEqual(typeof middleware.withResourceAuth, 'function');
    assert.strictEqual(typeof middleware.withPromptAuth, 'function');
  });

  it('creates auth client for account', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'alice@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'alice@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    // Create a test handler that validates auth context
    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // Execute handler with empty extra
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    // Verify auth context was injected
    assert.ok(capturedExtra, 'Extra should be captured');
    const typedExtra = capturedExtra as {
      authContext?: { accountId?: string; auth?: unknown };
    };
    assert.ok(typedExtra.authContext, 'Auth context should exist');
    assert.strictEqual(typedExtra.authContext.accountId, 'alice@outlook.com');
    assert.ok(typedExtra.authContext.auth, 'Auth client should exist');
  });

  it('enriches extra with auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'bob@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'bob@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    assert.ok(capturedExtra, 'Extra should be captured');
    const typedExtra = capturedExtra as {
      authContext?: unknown;
    };
    assert.ok(typedExtra.authContext, 'Auth context should exist');
  });

  it('preserves account ID in auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'charlie@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'charlie@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedAccountId: string | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedAccountId = extra.authContext.accountId;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    assert.strictEqual(capturedAccountId, 'charlie@outlook.com');
  });

  it('handler receives guaranteed auth (middleware catches errors)', async () => {
    // Valid token
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'valid@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'valid@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let handlerCalled = false;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      handlerCalled = true;
      // Handler can safely assume auth exists
      assert.ok(extra.authContext.auth);
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    assert.ok(handlerCalled, 'Handler should have been called');
  });

  it('multiple tool calls use same account', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'fixed@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'fixed@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    const accountIds: string[] = [];

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      accountIds.push(extra.authContext.accountId);
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // Execute handler multiple times
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    // All calls should use the same account
    assert.strictEqual(accountIds.length, 3);
    assert.ok(accountIds.every((id) => id === 'fixed@outlook.com'));
  });

  it('handles arg-less tools correctly', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'argless@outlook.com',
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: 'argless@outlook.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedArgs: unknown = null;
    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedArgs = args;
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // Call with only extra (arg-less tool pattern)
    await (toolModule.handler as (args: unknown) => Promise<unknown>)({});

    // Args should default to {}
    assert.deepStrictEqual(capturedArgs, {});
    assert.ok(capturedExtra, 'Extra should be captured');
    const typedExtra = capturedExtra as { authContext?: unknown };
    assert.ok(typedExtra.authContext);
  });

  it('handles special characters in account ID', async () => {
    const specialAccount = 'user+test@outlook.com';
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: specialAccount,
        service: 'outlook',
      }),
      realTokenData
    );
    await setActiveAccount(sharedTokenStore, {
      service: 'outlook',
      accountId: specialAccount,
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedAccountId: string | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedAccountId = extra.authContext.accountId;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    assert.strictEqual(capturedAccountId, specialAccount);
  });
});

// ============================================================================
// Multi-Account Switching Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Multi-Account Switching', () => {
  it('uses active account from tokenStore', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);
    await (wrapped.handler as Handler)({}, createTestExtra());
    assert.strictEqual(captured[0], 'alice@outlook.com');
  });

  it('switches accounts when active account changes', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com', 'bob@outlook.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'outlook', accountId: 'bob@outlook.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@outlook.com', 'bob@outlook.com']);
  });

  it('supports backchannel override via _meta.accountId', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    // Also add bob's token (but not as active account)
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@outlook.com', service: 'outlook' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@outlook.com' } });
    assert.strictEqual(captured[0], 'bob@outlook.com');
  });

  it('backchannel override takes precedence over active account', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@outlook.com', service: 'outlook' }), realTokenData);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'charlie@outlook.com', service: 'outlook' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@outlook.com' } });
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'charlie@outlook.com' } });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@outlook.com', 'bob@outlook.com', 'charlie@outlook.com', 'alice@outlook.com']);
  });

  it('handles multiple services independently', async () => {
    const { middleware: outlookAuth } = await setupTestContext(['alice@outlook.com']);

    // Create separate OneDrive provider (no accounts set up for it)
    const provider = new LoopbackOAuthProvider({
      service: 'drive',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: 'Files.Read',
      headless: true,
      logger,
      tokenStore: sharedTokenStore,
      tenantId: config.tenantId,
    });
    const driveAuth = provider.authMiddleware();

    const { captured: outlookCaptured, toolModule: outlookTool } = createCapturingTool((e) => e.authContext.accountId);
    const { toolModule: driveTool } = createCapturingTool((e) => e.authContext.accountId);

    const wrappedOutlook = outlookAuth.withToolAuth(outlookTool);
    const wrappedDrive = driveAuth.withToolAuth(driveTool);

    await (wrappedOutlook.handler as Handler)({}, createTestExtra());
    const driveResult = await (wrappedDrive.handler as AuthRequiredHandler)({}, createTestExtra());

    assert.strictEqual(outlookCaptured[0], 'alice@outlook.com');
    // OneDrive has no active account, so returns auth_required
    assert.ok(driveResult.structuredContent);
  });

  it('preserves _meta fields other than accountId', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    const { captured, toolModule } = createCapturingTool((e) => e._meta);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'alice@outlook.com', customField: 'test-value' } });

    assert.ok(captured[0]);
    assert.strictEqual((captured[0] as { accountId?: string; customField?: string }).accountId, 'alice@outlook.com');
    assert.strictEqual((captured[0] as { accountId?: string; customField?: string }).customField, 'test-value');
  });

  it('handles account switching with null intermediate state', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@outlook.com', service: 'outlook' }), realTokenData);

    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await removeAccount(sharedTokenStore, { service: 'outlook', accountId: 'alice@outlook.com' });

    const resultNoAccount = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.strictEqual(resultNoAccount.structuredContent?.result?.type, 'auth_required');

    await addAccount(sharedTokenStore, { service: 'outlook', accountId: 'bob@outlook.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());
  });

  it('supports rapid account switching without state pollution', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com', 'bob@outlook.com', 'charlie@outlook.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'outlook', accountId: 'bob@outlook.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'outlook', accountId: 'charlie@outlook.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'outlook', accountId: 'alice@outlook.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@outlook.com', 'bob@outlook.com', 'charlie@outlook.com', 'alice@outlook.com']);
  });

  it('concurrent requests with different overrides use correct accounts', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@outlook.com', service: 'outlook' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await Promise.all([(wrapped.handler as Handler)({}, createTestExtra()), (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@outlook.com' } }), (wrapped.handler as Handler)({}, createTestExtra())]);

    assert.strictEqual(captured.length, 3);
    const aliceCount = captured.filter((id) => id === 'alice@outlook.com').length;
    const bobCount = captured.filter((id) => id === 'bob@outlook.com').length;
    assert.strictEqual(aliceCount, 2);
    assert.strictEqual(bobCount, 1);
  });
});

// ============================================================================
// Error Handling Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Error Handling', () => {
  it('throws error for missing token when handler is called', async () => {
    // No token set for this account
    const middleware = sharedAuthProvider.authMiddleware();

    const testHandler = async (_args: unknown, _extra: EnrichedExtra): Promise<CallToolResult> => {
      return { content: [{ type: 'text', text: 'should not reach here' }] };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // The enhanced handler should return auth_required when token is missing
    const result = await (toolModule.handler as (args: unknown, extra: unknown) => Promise<{ structuredContent?: { type?: string } }>)({}, {});
    assert.ok(result.structuredContent);
    assert.strictEqual((result.structuredContent as { result?: { type?: string } }).result?.type, 'auth_required', 'Should return auth_required when token is missing');
  });

  it('throws error when no active account is set', async () => {
    const _userId = createTestUserId();
    const middleware = sharedAuthProvider.authMiddleware();
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.ok(result.structuredContent);
    assert.strictEqual(result.structuredContent.result?.type, 'auth_required');
  });

  it('throws error when active account has no token', async () => {
    const _userId = createTestUserId();
    await addAccount(sharedTokenStore, { service: 'outlook', accountId: 'missing@outlook.com' });

    const middleware = sharedAuthProvider.authMiddleware();
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.ok(result.structuredContent);
    assert.strictEqual(result.structuredContent.result?.type, 'auth_required');
  });

  it('backchannel override with invalid account fails gracefully', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, { ...createTestExtra(), _meta: { accountId: 'invalid@outlook.com' } });
    assert.strictEqual(result.structuredContent?.result?.type, 'auth_required');
  });

  it('rejects unauthorized account access (security)', async () => {
    const { middleware } = await setupTestContext(['alice@outlook.com']);
    await sharedTokenStore.delete(createAccountKey('token', { accountId: 'bob@outlook.com', service: 'outlook' }));

    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const bobResult = await (wrapped.handler as AuthRequiredHandler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@outlook.com' } });
    assert.strictEqual(bobResult.structuredContent?.result?.type, 'auth_required');

    const aliceResult = await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'alice@outlook.com' } });
    assert.ok(aliceResult);
  });
});
