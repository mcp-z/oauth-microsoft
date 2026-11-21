/**
 * DCR Test Server for Integration Testing
 * HTTP server with both MCP and DCR endpoints for full integration testing
 */

import type { ToolConfig, ToolHandler, ToolModule } from '@mcp-z/oauth';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { McpServer } from '@modelcontextprotocol/server';
import cors from 'cors';
import express from 'express';
import type { Server } from 'http';
import Keyv from 'keyv';
import type { Socket } from 'net';
import { z } from 'zod';
import { createDcrRouter, DcrOAuthProvider } from '../../../src/index.ts';
import { listenOnFreePort } from '../listen-on-free-port.ts';

export interface DcrTestServerConfig {
  /** Fixed port to run on; omit to bind an OS-assigned port on 127.0.0.1 (then baseUrl is derived) */
  port?: number;

  /** Base URL for OAuth endpoints; required with port, derived from the bound port without it */
  baseUrl?: string;

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
  const { scopes, clientId, clientSecret, tenantId } = config;

  // Use provided store or create in-memory store (no file persistence)
  const store = config.store || new Keyv();

  // Create Express app
  const app = express();

  // Without a fixed port, bind first so the base URL is built from the assigned port
  let httpServer: Server | undefined;
  let port = config.port;
  let baseUrl = config.baseUrl;
  if (port === undefined) {
    const bound = await listenOnFreePort(app, '127.0.0.1');
    httpServer = bound.server;
    port = bound.port;
    baseUrl = `http://127.0.0.1:${port}`;
  }
  if (baseUrl === undefined || port === undefined) throw new Error('baseUrl is required with port');
  const serverBaseUrl: string = baseUrl;

  // Parse JSON bodies (required for DCR endpoints)
  app.use(express.json());

  // Create simple echo tool for MCP testing with explicit ToolModule type
  const tools: ToolModule[] = [
    {
      name: 'echo',
      config: {
        title: 'Echo Tool',
        description: 'Echoes back the provided message and auth context',
        inputSchema: z.object({ message: z.string() }),
        outputSchema: z.object({
          echo: z.string(),
          accountId: z.string().optional(), // User email from auth context
        }),
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

  // Setup HTTP server with MCP endpoints at /mcp using NodeStreamableHTTPServerTransport
  const mcpRouter = express.Router();

  // Configure CORS for MCP endpoint
  mcpRouter.use(
    cors({
      origin: '*',
      // Stateless: no session id is ever issued, so there is nothing to expose.
      // 'authorization' is required for the DCR bearer flow; 'mcp-protocol-version'
      // is required on HTTP requests as of spec 2025-06-18.
      allowedHeaders: ['content-type', 'authorization', 'mcp-protocol-version'],
    })
  );

  // Handle MCP requests with stateless transport
  mcpRouter.post('/', async (req, res) => {
    const transport = new NodeStreamableHTTPServerTransport({
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

  // Start HTTP server (already bound when no fixed port was given)
  if (!httpServer) {
    httpServer = app.listen(port, () => {
      console.log(`🔧 DCR Test Server listening on ${baseUrl}`);
      console.log(`   MCP endpoint: ${baseUrl}/mcp`);
      console.log(`   DCR endpoints: ${baseUrl}/.well-known/oauth-authorization-server`);
    });
  }
  const listening: Server = httpServer;
  const connections = new Set<Socket>();
  listening.on('connection', (socket) => {
    connections.add(socket);
    socket.once('close', () => connections.delete(socket));
  });

  return {
    url: serverBaseUrl,
    store,
    close: async () => {
      const closed = new Promise<void>((resolve, reject) => {
        listening.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      if (typeof listening.closeAllConnections === 'function') {
        listening.closeAllConnections();
      } else {
        for (const socket of connections) socket.destroy();
      }
      return closed;
    },
  };
}
