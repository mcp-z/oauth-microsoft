/**
 * DCR Test Server for Integration Testing
 * HTTP server with both MCP and DCR endpoints for full integration testing
 */

import type { ToolConfig, ToolHandler, ToolModule } from '@mcp-z/oauth';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import cors from 'cors';
import express from 'express';
import type { Server } from 'http';
import Keyv from 'keyv';
import { z } from 'zod';
import { createDcrRouter, DcrOAuthProvider } from '../../../src/index.ts';

export interface DcrTestServerConfig {
  /** Port to run server on */
  port: number;

  /** Base URL for OAuth endpoints */
  baseUrl: string;

  /** OAuth scopes to support */
  scopes: string[];

  /** Client ID for upstream Microsoft OAuth */
  clientId: string;

  /** Client secret for upstream Microsoft OAuth (optional for public clients) */
  clientSecret?: string;

  /** Tenant ID for Microsoft OAuth */
  tenantId?: string;

  /** Optional pre-configured store (for automated testing) */
  store?: Keyv;
}

/**
 * Start DCR test server with both MCP and DCR endpoints
 * Returns URL, store, and close function
 */
export async function startDcrTestServer(config: DcrTestServerConfig): Promise<{ url: string; store: Keyv; close: () => Promise<void> }> {
  const { port, baseUrl, scopes, clientId, clientSecret, tenantId } = config;

  // Use provided store or create in-memory store (no file persistence)
  const store = config.store || new Keyv();

  // Create Express app
  const app = express();

  // Parse JSON bodies (required for DCR endpoints)
  app.use(express.json());

  // Create simple echo tool for MCP testing with explicit ToolModule type
  const tools: ToolModule[] = [
    {
      name: 'echo',
      config: {
        title: 'Echo Tool',
        description: 'Echoes back the provided message and auth context',
        inputSchema: { message: z.string() },
        outputSchema: {
          echo: z.string(),
          accountId: z.string().optional(), // User email from auth context
        },
      },
      handler: async (args: { message: string }, extra: Record<string, unknown>): Promise<CallToolResult> => {
        const { message } = args;

        // Extract accountId from authContext if present
        const authContext = extra.authContext as { accountId?: string } | undefined;
        const accountId = authContext?.accountId;

        const output = {
          echo: `DCR test echo: ${message}`,
          ...(accountId && { accountId }),
        };

        return {
          content: [{ type: 'text' as const, text: JSON.stringify(output) }],
          structuredContent: output,
        };
      },
    } satisfies ToolModule,
  ];

  // Create silent logger for tests (avoids console output interfering with test assertions)
  const silentLogger = {
    info: () => {},
    error: () => {},
    warn: () => {},
    debug: () => {},
  };

  // Create DCR provider for auth middleware
  const provider = new DcrOAuthProvider({
    clientId,
    ...(clientSecret && { clientSecret }),
    tenantId: tenantId || 'common',
    scope: scopes.join(' '),
    verifyEndpoint: `${baseUrl}/oauth/verify`,
    logger: silentLogger,
  });

  // Apply DCR auth middleware to tools
  const authMiddleware = provider.authMiddleware();

  // MCP server factory
  const createMcpServer = () => {
    const server = new McpServer({
      name: 'dcr-test-server',
      version: '1.0.0',
    });

    // Register tools with DCR auth middleware applied
    for (const tool of tools) {
      const wrapped = authMiddleware.withToolAuth(tool);
      server.registerTool(wrapped.name, wrapped.config as ToolConfig, wrapped.handler as ToolHandler);
    }

    return server;
  };

  // Setup HTTP server with MCP endpoints at /mcp using StreamableHTTPServerTransport
  const mcpRouter = express.Router();

  // Configure CORS for MCP endpoint
  mcpRouter.use(
    cors({
      origin: '*',
      exposedHeaders: ['Mcp-Session-Id'],
      allowedHeaders: ['Content-Type', 'mcp-session-id'],
    })
  );

  // Handle MCP requests with stateless transport
  mcpRouter.post('/', async (req, res) => {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // Stateless mode
    });

    // Cleanup transport when request closes
    res.on('close', () => {
      transport.close();
    });

    const mcpServerInstance = createMcpServer();
    await mcpServerInstance.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Mount MCP router at /mcp
  app.use('/mcp', mcpRouter);

  // Create DCR router
  const dcrRouter = createDcrRouter({
    store,
    issuerUrl: baseUrl,
    baseUrl,
    scopesSupported: scopes,
    clientConfig: {
      clientId,
      ...(clientSecret && { clientSecret }),
      ...(tenantId && { tenantId }),
    },
  });

  // Mount DCR router at root (OAuth endpoints)
  app.use('/', dcrRouter);

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', port, baseUrl, mcp: `${baseUrl}/mcp` });
  });

  // Start HTTP server
  const httpServer: Server = app.listen(port, () => {
    console.log(`🔧 DCR Test Server listening on ${baseUrl}`);
    console.log(`   MCP endpoint: ${baseUrl}/mcp`);
    console.log(`   DCR endpoints: ${baseUrl}/.well-known/oauth-authorization-server`);
  });

  return {
    url: baseUrl,
    store,
    close: async () => {
      // Close HTTP server
      // First, close all active connections to prevent hanging
      httpServer.closeAllConnections();

      return new Promise<void>((resolve, reject) => {
        httpServer.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    },
  };
}
