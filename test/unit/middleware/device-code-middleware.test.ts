/**
 * DeviceCodeProvider Middleware Tests
 *
 * Tests for authMiddleware() behavior with device code authentication.
 * Validates auth client creation, context injection, and error handling.
 *
 * Note: DeviceCodeProvider uses a single static identity pattern (accountId='device-code')
 * similar to service accounts - no multi-account switching supported.
 */

import { createAccountKey } from '@mcp-z/oauth';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import * as fs from 'fs';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { DeviceCodeProvider, type EnrichedExtra, type ToolModule } from '../../../src/index.ts';
import { createConfig } from '../../lib/config.ts';
import { logger } from '../../lib/test-utils.ts';

const config = createConfig();

let sharedTokenStore: Keyv;
let sharedAuthProvider: DeviceCodeProvider;
let realTokenData: unknown;

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

  realTokenData = await testTokenStore.get(outlookTokenKey);
  if (!(realTokenData as { accessToken?: string })?.accessToken) {
    throw new Error('Token found but missing accessToken field. Run `npm run test:setup` to regenerate.');
  }

  // Create shared token store for all tests (in-memory)
  sharedTokenStore = new Keyv();

  // Create production DeviceCodeProvider
  sharedAuthProvider = new DeviceCodeProvider({
    service: 'outlook',
    clientId: config.clientId,
    tenantId: config.tenantId,
    scope: 'User.Read Mail.ReadWrite',
    headless: true,
    logger,
    tokenStore: sharedTokenStore,
  });
});

// Clean token store before each test to prevent state pollution
beforeEach(async () => {
  // Clear all keys from shared token store
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
// Basic Functionality Tests (Fixed Device-Code Pattern)
// ============================================================================

describe('DeviceCodeProvider Middleware - Basic Functionality', () => {
  it('creates middleware wrapper function', () => {
    const middleware = sharedAuthProvider.authMiddleware();
    assert.strictEqual(typeof middleware.withToolAuth, 'function');
  });

  it('creates auth client with fixed device-code account', async () => {
    // Setup token for device-code account
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

    // Execute handler
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});

    // Verify auth context was injected
    assert.ok(capturedExtra, 'Extra should be captured');
    const typedExtra = capturedExtra as {
      authContext?: { accountId?: string; auth?: unknown };
    };
    assert.ok(typedExtra.authContext, 'Auth context should exist');
    assert.strictEqual(typedExtra.authContext.accountId, 'device-code');
    assert.ok(typedExtra.authContext.auth, 'Auth client should exist');
  });

  it('enriches extra with auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

  it('preserves device-code account ID in auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

    assert.strictEqual(capturedAccountId, 'device-code');
  });

  it('handler receives guaranteed auth (middleware catches errors)', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

  it('multiple tool calls use same device-code account', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

    // All calls should use the same device-code account
    assert.strictEqual(accountIds.length, 3);
    assert.ok(accountIds.every((id) => id === 'device-code'));
  });

  it('handles arg-less tools correctly', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'device-code',
        service: 'outlook',
      }),
      realTokenData
    );

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

    // Verify extra was captured with auth context
    assert.ok(capturedExtra, 'Extra should be captured');
    const typedExtra = capturedExtra as { authContext?: unknown };
    assert.ok(typedExtra.authContext);
    // Note: capturedArgs receives the same enriched extra object (middleware behavior)
    assert.ok(capturedArgs === capturedExtra, 'Args and extra should be same object for arg-less tools');
  });
});

// ============================================================================
// Error Handling Tests
// ============================================================================

describe('DeviceCodeProvider Middleware - Error Handling', () => {
  it('throws error when token is missing (headless mode)', async () => {
    const middleware = sharedAuthProvider.authMiddleware();

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      // Actually call the auth provider to trigger token fetch
      await extra.authContext.auth.getAccessToken();
      return { content: [{ type: 'text', text: 'should not reach here' }] };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // The middleware should wrap the error when auth provider is used
    await assert.rejects(
      async () => {
        await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});
      },
      (error: Error) => {
        assert.ok(error.message.includes('Device code authentication failed'), 'Should mention device code auth failed');
        assert.ok(error.message.includes('headless mode'), 'Should mention headless mode restriction');
        return true;
      }
    );
  });

  it('wraps authentication errors with helpful context', async () => {
    // Create provider that will fail due to invalid config
    const invalidProvider = new DeviceCodeProvider({
      service: 'outlook',
      clientId: 'invalid-client-id',
      tenantId: 'invalid-tenant',
      scope: 'User.Read',
      headless: true,
      logger,
      tokenStore: new Keyv(), // Empty store
    });

    const middleware = invalidProvider.authMiddleware();

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      // Actually call the auth provider to trigger token fetch
      await extra.authContext.auth.getAccessToken();
      return { content: [{ type: 'text', text: 'should not reach here' }] };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    // Should wrap the error with "Device code authentication failed" context
    await assert.rejects(
      async () => {
        await (toolModule.handler as (args: unknown, extra: unknown) => Promise<unknown>)({}, {});
      },
      (error: Error) => {
        assert.ok(error.message.includes('Device code authentication failed'), 'Should include failure context');
        return true;
      }
    );
  });
});
