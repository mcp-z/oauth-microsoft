#!/usr/bin/env node
/**
 * Minimal Outlook MCP stdio test server
 *
 * PURPOSE: Test Microsoft OAuth stateless mode without cross-dependencies
 * FEATURES:
 * - Full MCP SDK (McpServer, StdioServerTransport)
 * - Stateless mode: extracts OAuth token from MCP context
 * - Minimal outlook-message-search and outlook-account-current tools
 * - Real Microsoft Graph API calls
 * - Process-based communication (stdin/stdout)
 * - Graceful shutdown on SIGINT/SIGTERM
 *
 * USAGE: node test/lib/servers/outlook-stdio.ts
 * NOTE: This is a minimal test fixture - NOT a production Outlook server
 */

import type { ToolConfig } from '@mcp-z/oauth';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { CallToolResult, ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

/**
 * Extract OAuth token from MCP context (stateless mode)
 * MCP SDK provides tokens in extra._meta.oauth.token
 */
function extractTokenFromContext(extra: RequestHandlerExtra<ServerRequest, ServerNotification>): string {
  // Type-safe access to optional OAuth token in meta
  const token = (extra._meta as { oauth?: { token?: string } } | undefined)?.oauth?.token;
  if (!token || typeof token !== 'string') {
    throw new Error('No OAuth token provided in MCP context. Client must provide token via capabilities.experimental.oauth');
  }
  return token;
}

async function main() {
  const server = new McpServer({
    name: 'outlook-stdio-test',
    version: '1.0.0',
  });

  // Register outlook-message-search tool with explicit ToolConfig type
  const messageSearchConfig: ToolConfig = {
    title: 'Search Outlook Messages',
    description: 'Search messages in Outlook mailbox',
    inputSchema: {
      fields: z.string().optional(),
      query: z.string().optional(),
    },
    outputSchema: {
      messages: z.array(
        z.object({
          id: z.string(),
          subject: z.string().optional(),
        })
      ),
    },
  };

  server.registerTool('outlook-message-search', messageSearchConfig, async (_args: unknown, extra: unknown): Promise<CallToolResult> => {
    try {
      // Extract token from MCP context (stateless mode)
      const accessToken = extractTokenFromContext(extra as RequestHandlerExtra<ServerRequest, ServerNotification>);

      // Make real Microsoft Graph API call
      const response = await fetch('https://graph.microsoft.com/v1.0/me/messages?$top=10&$select=id,subject,from', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Microsoft Graph API error: ${response.status} ${response.statusText}`);
      }

      const data = (await response.json()) as { value?: Array<{ id: string; subject?: string }> };

      return {
        content: [{ type: 'text', text: JSON.stringify({ messages: data.value || [] }) }],
        structuredContent: { messages: data.value || [] },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        content: [{ type: 'text', text: JSON.stringify({ error: errorMessage }) }],
        isError: true,
      };
    }
  });

  // Register outlook-account-current tool with explicit ToolConfig type
  const accountCurrentConfig: ToolConfig = {
    title: 'Get Current Outlook Account',
    description: 'Get current authenticated Outlook account',
    outputSchema: {
      email: z.string(),
    },
  };

  server.registerTool('outlook-account-current', accountCurrentConfig, async (extra: unknown): Promise<CallToolResult> => {
    try {
      // Extract token from MCP context (stateless mode)
      const accessToken = extractTokenFromContext(extra as RequestHandlerExtra<ServerRequest, ServerNotification>);

      // Make real Microsoft Graph API call to get user email
      const response = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Microsoft Graph API error: ${response.status} ${response.statusText}`);
      }

      const data = (await response.json()) as { mail?: string; userPrincipalName?: string };
      const email = data.mail || data.userPrincipalName || '';

      return {
        content: [{ type: 'text', text: JSON.stringify({ email }) }],
        structuredContent: { email },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        content: [{ type: 'text', text: JSON.stringify({ error: errorMessage }) }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();
