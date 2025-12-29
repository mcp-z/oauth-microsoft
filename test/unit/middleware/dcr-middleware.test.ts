/**
 * DcrOAuthProvider AuthMiddleware Tests
 *
 * Tests for DcrOAuthProvider.authMiddleware() - validates bearer token extraction,
 * token verification, auth context enrichment, and error handling.
 *
 * Unlike LoopbackOAuthProvider (which uses token storage), DcrOAuthProvider is stateless:
 * - Receives bearer tokens from HTTP Authorization header
 * - Validates tokens via /oauth/verify endpoint
 * - Enriches extra with auth context from provider tokens
 */

import '../../lib/env-loader.ts';
import type { ProviderTokens } from '@mcp-z/oauth';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import express from 'express';
import type { Server } from 'http';
import { z } from 'zod';
import { DcrOAuthProvider, type EnrichedExtra, type ToolModule } from '../../../src/index.ts';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

const TEST_PORT = 9876;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const VERIFY_ENDPOINT = `${BASE_URL}/oauth/verify`;

// Mock provider tokens for testing
const mockProviderTokens: ProviderTokens = {
  accessToken: 'mock_provider_access_token',
  refreshToken: 'mock_provider_refresh_token',
  expiresAt: Date.now() + 3600000,
  scope: 'User.Read Mail.Read',
};

// Simple test tool for middleware validation
const testTool = {
  name: 'test-tool',
  config: {
    title: 'Test Tool',
    description: 'Tool for testing authMiddleware',
    inputSchema: z.object({ message: z.string() }),
    outputSchema: z.object({ result: z.string() }),
  },
  handler: async (_args: unknown, extra: unknown) => {
    // Handler expects authContext to be present
    assert.ok((extra as EnrichedExtra).authContext, 'authContext should be present');
    assert.ok((extra as EnrichedExtra).authContext.auth, 'auth should be present');

    return {
      content: [{ type: 'text', text: JSON.stringify({ result: 'success' }) }],
      structuredContent: { result: 'success' },
    };
  },
} satisfies ToolModule;

// Create minimal HTTP server for verify endpoint
let testServer: Server | undefined;
const validBearerToken = 'valid_dcr_token';

function startTestServer(): Promise<void> {
  const app = express();
  app.use(express.json());

  // Mock /oauth/verify endpoint
  app.get('/oauth/verify', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'missing_token' });
    }

    const token = authHeader.replace(/^Bearer\s+/i, '');

    if (token === validBearerToken) {
      return res.json({ providerTokens: mockProviderTokens });
    }

    return res.status(401).json({ error: 'invalid_token' });
  });

  return new Promise((resolve) => {
    testServer = app.listen(TEST_PORT, () => {
      resolve();
    });
  });
}

function stopTestServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!testServer) {
      resolve();
      return;
    }

    testServer.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

describe('DcrOAuthProvider.authMiddleware()', () => {
  let provider: DcrOAuthProvider;
  let originalGetUserEmail: (tokens: ProviderTokens) => Promise<string>;

  before(async () => {
    await startTestServer();

    provider = new DcrOAuthProvider({
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      tenantId: 'common',
      scope: 'User.Read Mail.Read',
      verifyEndpoint: VERIFY_ENDPOINT,
      logger,
    });

    // Save original getUserEmail method
    originalGetUserEmail = provider.getUserEmail.bind(provider);
  });

  after(async () => {
    await stopTestServer();
  });

  beforeEach(() => {
    // Stub getUserEmail to avoid real API calls in tests
    provider.getUserEmail = async (_tokens) => 'test@outlook.com';
  });

  afterEach(() => {
    // Restore original method after each test
    provider.getUserEmail = originalGetUserEmail;
  });

  it('throws error when Authorization header missing', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = createTestExtra({
      requestInfo: { headers: {} }, // No Authorization header
    });

    try {
      await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.ok(error instanceof Error);
      assert.ok(error.message.includes('Authorization') || error.message.includes('bearer'), `Expected auth error, got: ${error.message}`);
    }
  });

  it('throws error when bearer token is invalid', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = createTestExtra({
      requestInfo: {
        headers: {
          authorization: 'Bearer invalid_token_12345',
        },
      },
    });

    try {
      await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.ok(error instanceof Error);
      assert.ok(error.message.includes('verification failed') || error.message.includes('401'), `Expected verification error, got: ${error.message}`);
    }
  });

  it('enriches extra with authContext when token is valid', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = createTestExtra({
      requestInfo: {
        headers: {
          authorization: `Bearer ${validBearerToken}`,
        },
      },
    });

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual(result.structuredContent?.result, 'success');
  });

  it('extracts bearer token from authInfo when present', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = createTestExtra({
      requestInfo: { headers: {} },
      authInfo: {
        token: validBearerToken, // SDK already extracted token
        clientId: 'test-client',
        scopes: [],
      },
    });

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual(result.structuredContent?.result, 'success');
  });

  it('handles case-insensitive Bearer prefix', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    // Test lowercase 'bearer'
    const extraLower = createTestExtra({
      requestInfo: {
        headers: {
          authorization: `bearer ${validBearerToken}`,
        },
      },
    });

    const resultLower = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extraLower);
    assert.ok(resultLower);

    // Test mixed case 'BeArEr'
    const extraMixed = createTestExtra({
      requestInfo: {
        headers: {
          authorization: `BeArEr ${validBearerToken}`,
        },
      },
    });

    const resultMixed = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extraMixed);
    assert.ok(resultMixed);
  });

  it('auth provider can get access token from provider tokens', async () => {
    const auth = provider.toAuthProvider(mockProviderTokens);

    const accessToken = await auth.getAccessToken();

    assert.ok(accessToken);
    assert.strictEqual(accessToken, mockProviderTokens.accessToken);
  });

  it('sets accountId to user email from getUserEmail()', async () => {
    const testEmail = 'user@outlook.com';

    // Override the beforeEach stub with a specific email
    provider.getUserEmail = async (_tokens) => testEmail;

    const middleware = provider.authMiddleware();

    // Create tool that captures accountId
    let capturedAccountId: string | undefined;
    const captureTool = {
      name: 'capture-tool',
      config: testTool.config,
      handler: async (_args: unknown, extra: unknown) => {
        capturedAccountId = (extra as EnrichedExtra).authContext.accountId;
        return { content: [], structuredContent: { result: 'ok' } };
      },
    } satisfies ToolModule;

    const wrappedTool = middleware.withToolAuth(captureTool);

    const extra = createTestExtra({
      requestInfo: {
        headers: { authorization: `Bearer ${validBearerToken}` },
      },
    });

    await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.strictEqual(capturedAccountId, testEmail, 'accountId should be user email');
  });
});
