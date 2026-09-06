import '../../lib/env-loader.ts';

/**
 * DcrOAuthProvider Tests
 *
 * Tests for the DcrOAuthProvider class which implements stateless OAuth 2.0 for
 * Dynamic Client Registration scenarios, and for authMiddleware() which validates
 * bearer token extraction, token verification, auth context enrichment, and error handling.
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import { DcrOAuthProvider, type DcrOAuthProviderConfig, type EnrichedExtra, type ToolModule } from '@mcp-z/oauth-microsoft';
import type { CallToolResult } from '@modelcontextprotocol/server';
import assert from 'assert';
import express from 'express';
import type { Server } from 'http';
import { createServer } from 'http';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { z } from 'zod';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

describe('DcrOAuthProvider', () => {
  let server: Server;
  let tenantId: string;
  let provider: DcrOAuthProvider;

  before(async () => {
    // Create mock Microsoft token endpoint
    return new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        let body = '';

        req.on('data', (chunk) => {
          body += chunk.toString();
        });

        req.on('end', () => {
          // Only respond to /token endpoint
          if (req.url !== '/token') {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'not_found' }));
            return;
          }

          const params = new URLSearchParams(body);
          const grantType = params.get('grant_type');
          const refreshToken = params.get('refresh_token');

          if (grantType === 'refresh_token' && refreshToken === 'valid_refresh_token') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                access_token: 'refreshed_access_token',
                expires_in: 3600,
                scope: 'Mail.Read Mail.Send',
              })
            );
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid refresh token' }));
          }
        });
      });

      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address !== 'string') {
          tenantId = 'common'; // Use standard tenant ID for production code path

          const config: DcrOAuthProviderConfig = {
            clientId: 'test_client_id',
            clientSecret: 'test_client_secret',
            tenantId,
            scope: 'Mail.Read Mail.Send',
            tokenUrl: `http://127.0.0.1:${address.port}/token`, // Point to mock server
            verifyEndpoint: 'http://test.invalid/oauth/verify', // Not used in these tests
            logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
          };

          provider = new DcrOAuthProvider(config);
          resolve();
        }
      });
    });
  });

  after(() => {
    server.close();
  });

  it('creates auth provider from valid tokens', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'valid_access_token',
      refreshToken: 'valid_refresh_token',
      expiresAt: Date.now() + 3600000, // Valid for 1 hour
      scope: 'Mail.Read',
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    assert.strictEqual(accessToken, 'valid_access_token');
  });

  it('refreshes expired token automatically', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      refreshToken: 'valid_refresh_token',
      expiresAt: Date.now() - 1000, // Expired 1 second ago
      scope: 'Mail.Read',
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    // Should return refreshed token
    assert.strictEqual(accessToken, 'refreshed_access_token');
  });

  it('throws error when token expired and no refresh token', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      expiresAt: Date.now() - 1000, // Expired
      // No refresh token
    };

    const auth = provider.toAuthProvider(tokens);

    await assert.rejects(async () => {
      await auth.getAccessToken();
    }, /Access token expired and no refresh token available/);
  });

  it('throws error when refresh fails', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'expired_access_token',
      refreshToken: 'invalid_refresh_token',
      expiresAt: Date.now() - 1000, // Expired
    };

    const auth = provider.toAuthProvider(tokens);

    await assert.rejects(async () => {
      await auth.getAccessToken();
    }, /Token refresh failed/);
  });

  it('handles tokens without expiry (assumes valid)', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'no_expiry_token',
      // No expiresAt field
    };

    const auth = provider.toAuthProvider(tokens);
    const accessToken = await auth.getAccessToken();

    assert.strictEqual(accessToken, 'no_expiry_token');
  });

  it('supports multiple auth providers from same tokens', async () => {
    const tokens: ProviderTokens = {
      accessToken: 'shared_token',
      expiresAt: Date.now() + 3600000,
    };

    const auth1 = provider.toAuthProvider(tokens);
    const auth2 = provider.toAuthProvider(tokens);

    const token1 = await auth1.getAccessToken();
    const token2 = await auth2.getAccessToken();

    // Both should return the same token (stateless)
    assert.strictEqual(token1, 'shared_token');
    assert.strictEqual(token2, 'shared_token');
  });
});

// Integration tests with real Microsoft endpoints (require tokens from test-setup)
describe('DcrOAuthProvider - Integration with Microsoft APIs', () => {
  it('should refresh provider tokens with real Microsoft endpoint', async function () {
    this.timeout(30000);

    // Load stored DCR tokens from test-setup
    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({
      store: new KeyvFile({ filename: dcrTokenPath }),
    });

    interface DcrTokenData {
      clientId: string;
      clientSecret: string;
      providerRefreshToken: string;
      providerAccessToken: string;
      providerExpiresAt: number;
    }

    const storedTokens = (await dcrStore.get('microsoft')) as DcrTokenData | undefined;
    assert.ok(storedTokens, 'No stored DCR tokens - run the DCR flow first');

    const clientId = process.env.MS_CLIENT_ID;
    assert.ok(clientId, 'MS_CLIENT_ID must be set');
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID || 'common';

    const realProvider = new DcrOAuthProvider({
      clientId,
      ...(process.env.MS_TEST_DCR_CLIENT_SECRET && { clientSecret: process.env.MS_TEST_DCR_CLIENT_SECRET }),
      tenantId,
      scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read',
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
    });

    // Test refresh with real Microsoft endpoint
    console.log('🔄 Refreshing tokens with real Microsoft endpoint...');
    const refreshedTokens = await realProvider.refreshAccessToken(storedTokens.providerRefreshToken);

    assert.ok(refreshedTokens.accessToken, 'Should return new access token');
    assert.ok(refreshedTokens.accessToken !== storedTokens.providerAccessToken || refreshedTokens.expiresAt, 'Should have new token or fresh expiry');
    console.log(`✅ Refreshed token: ${refreshedTokens.accessToken.substring(0, 20)}...`);

    // Verify the refreshed token works by calling getUserEmail
    console.log('🔍 Verifying refreshed token with Microsoft Graph API...');
    const email = await realProvider.getUserEmail(refreshedTokens);
    assert.ok(email, 'Should get user email with refreshed token');
    assert.ok(email.includes('@'), 'Email should be valid format');
    console.log(`✅ Verified - user email: ${email}`);
  });

  it('should fail refresh with invalid token', async function () {
    this.timeout(10000);

    const clientId = process.env.MS_CLIENT_ID;
    assert.ok(clientId, 'MS_CLIENT_ID must be set');
    const tenantId = process.env.MS_TEST_DCR_TENANT_ID || 'common';

    const realProvider = new DcrOAuthProvider({
      clientId,
      ...(process.env.MS_TEST_DCR_CLIENT_SECRET && { clientSecret: process.env.MS_TEST_DCR_CLIENT_SECRET }),
      tenantId,
      scope: 'https://graph.microsoft.com/Mail.Read',
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
    });

    // Test refresh with invalid token
    await assert.rejects(
      async () => {
        await realProvider.refreshAccessToken('invalid_refresh_token_12345');
      },
      /Token refresh failed/,
      'Should throw error for invalid refresh token'
    );
    console.log('✅ Invalid refresh token correctly rejected by Microsoft');
  });
});

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
      http: { req: new Request('http://test.local') }, // No Authorization header
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
      http: { req: new Request('http://test.local', { headers: { authorization: 'Bearer invalid_token_12345' } }) },
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
      http: { req: new Request('http://test.local', { headers: { authorization: `Bearer ${validBearerToken}` } }) },
    });

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual((result.structuredContent as { result?: string }).result, 'success');
  });

  it('extracts bearer token from authInfo when present', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = createTestExtra({
      http: {
        req: new Request('http://test.local'),
        authInfo: {
          token: validBearerToken, // SDK already extracted token
          clientId: 'test-client',
          scopes: [],
        },
      },
    });

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual((result.structuredContent as { result?: string }).result, 'success');
  });

  it('handles case-insensitive Bearer prefix', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    // Test lowercase 'bearer'
    const extraLower = createTestExtra({
      http: { req: new Request('http://test.local', { headers: { authorization: `bearer ${validBearerToken}` } }) },
    });

    const resultLower = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extraLower);
    assert.ok(resultLower);

    // Test mixed case 'BeArEr'
    const extraMixed = createTestExtra({
      http: { req: new Request('http://test.local', { headers: { authorization: `BeArEr ${validBearerToken}` } }) },
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
      http: { req: new Request('http://test.local', { headers: { authorization: `Bearer ${validBearerToken}` } }) },
    });

    await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.strictEqual(capturedAccountId, testEmail, 'accountId should be user email');
  });
});
