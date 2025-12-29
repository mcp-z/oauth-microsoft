# @mcp-z/oauth-microsoft Architecture

> Technical architecture documentation for the Microsoft OAuth library used by MCP servers

---

## Overview

This library provides Microsoft OAuth 2.0 authentication (via MSAL - Microsoft Authentication Library) with multi-account support for MCP (Model Context Protocol) servers. It implements two complementary OAuth patterns: **Loopback OAuth** for desktop/CLI apps and **MCP SDK OAuth** for web-based stateless deployments.

**Core Design Principles**:
- **SOLID compliance**: Single Responsibility, Dependency Inversion, Inversion of Control
- **Middleware-based architecture**: Tools focus on business logic, middleware handles auth
- **Multi-account orchestration**: Service-level isolation with independent active accounts
- **Swappable storage**: Keyv interface with FileStore, Redis, DuckDB, PostgreSQL backends
- **Tenant-aware**: Support for common, organizations, and consumers tenants

---

## OAuth Provider Comparison

### LoopbackOAuthProvider

**Purpose**: Interactive OAuth flow for desktop/CLI applications using RFC 8252 loopback pattern.

**Characteristics**:
- Ephemeral local HTTP server on OS-assigned port
- Browser-based user authentication via Microsoft identity platform
- PKCE (Proof Key for Code Exchange) for security
- Server-side token storage (FileStore, DuckDB, Redis, PostgreSQL)
- Supports multi-account via token store + accountId
- Works with stdio and HTTP transports
- Tenant-aware (common, organizations, consumers)

**Use Cases**:
- Desktop applications
- CLI tools
- MCP servers with local execution
- Development and testing

**Security Features**:
- Binds to `127.0.0.1` only (localhost isolation)
- OS-assigned ports (eliminates port conflicts)
- PKCE prevents authorization code interception
- No redirect URI conflicts across instances
- Tenant isolation via configuration

### McpOAuthProvider

**Purpose**: Stateless OAuth for web-based MCP clients where client manages auth flow.

**Characteristics**:
- Client-initiated OAuth flow
- Tokens transmitted in request metadata (`extra.authInfo.token`)
- No server-side token storage (stateless)
- **REQUIRES HTTPS in production** (tokens in HTTP headers)
- HTTP transport only (no stdio)
- Client manages multi-account, token refresh, expiration
- Tenant configuration via server setup

**Use Cases**:
- Web-based MCP clients (like Claude Web)
- Multi-tenant SaaS applications
- Shared server instances with many clients
- Client-side token management

**Security Requirements**:
- **HTTPS mandatory** for network-accessible deployments
- Token validation on every request
- Client responsible for secure token storage
- Server never logs tokens (auto-sanitized)

**Comparison Table**:

| Feature | Loopback OAuth | MCP SDK OAuth |
|---------|----------------|---------------|
| Token Storage | Server (FileStore/DuckDB/Redis) | Client |
| OAuth Flow | Server initiates | Client initiates |
| Browser Required | Yes (server-side) | Yes (client-side) |
| Transport Support | stdio, HTTP | HTTP only |
| Multi-Account | Server manages via tokenStore | Client manages |
| Token Refresh | Server handles | Client handles |
| Tenant Support | Configured per client | Configured per server |
| HTTPS Required | No (localhost only) | **Yes (production)** |
| Use Case | Desktop/CLI tools | Web applications |

---

## Microsoft Tenant Architecture

### Tenant Types

Microsoft supports three tenant types for multi-tenant authentication:

**1. Common Tenant** (`tenantId: 'common'`):
- Allows sign-in from any Microsoft account (personal or work/school)
- Users from any Azure AD tenant can authenticate
- Most flexible option
- **Default for multi-account scenarios**

**2. Organizations Tenant** (`tenantId: 'organizations'`):
- Restricts to work/school accounts only (Azure AD)
- Blocks personal Microsoft accounts
- Enterprise/corporate deployments

**3. Consumers Tenant** (`tenantId: 'consumers'`):
- Restricts to personal Microsoft accounts only
- Blocks work/school accounts
- Consumer applications

**4. Specific Tenant** (`tenantId: 'guid'`):
- Single Azure AD tenant (organization-specific)
- Highest security isolation
- Fixed-account deployments

**Configuration**:
```typescript
const loopback = new LoopbackOAuthProvider({
  tokenStore,
  tenantId: 'common',  // or 'organizations', 'consumers', or specific GUID
  clientId: process.env.MICROSOFT_CLIENT_ID!,
  scopes: ['Mail.ReadWrite', 'Mail.Send'],
  logger,
});
```

**Best Practices**:
- **Multi-account tools**: Use `'common'` to allow any Microsoft account
- **Enterprise apps**: Use `'organizations'` or specific tenant GUID
- **Consumer apps**: Use `'consumers'` for personal accounts only
- **Security**: Specific tenant GUID provides strongest isolation

---

## OAuth Deployment Modes

The library supports distinct deployment patterns through the LoopbackOAuthProvider.

### Mode 1: Single-User (Desktop/CLI)

**Use Case**: Single user runs the process locally (desktop apps, CLI tools).

**Configuration**:
```typescript
const loopback = new LoopbackOAuthProvider({
  tokenStore,
  clientId: process.env.MICROSOFT_CLIENT_ID,
  tenantId: 'common',  // or 'organizations', 'consumers', or specific tenant GUID
  scopes: ['Mail.ReadWrite', 'Mail.Send'],
  logger,
});

const middleware = loopback.authMiddleware();
```

**Behavior**:
- All API calls use the single user's authenticated account
- **accountId is the user's email address** fetched from Microsoft Graph API
- Token storage: `user:default:{email}:{service}:token`
- Interactive OAuth flow via ephemeral loopback server
- Email automatically retrieved during first OAuth flow

**Use Cases**: Personal CLI tools, desktop applications, development environments.

**Tenant Configuration**: Use `'common'` for flexibility, or specific tenant GUID for security.

### Mode 2: Stateless (MCP OAuth)

**Use Case**: Web-based MCP clients where client manages OAuth flow and tokens.

**Configuration**:
```typescript
import { setupMcpOAuth, McpOAuthProvider } from '@mcp-z/oauth-microsoft';

const app = express();

// Setup MCP OAuth endpoints
const mcpOAuthAdapter = setupMcpOAuth(app, {
  tenantId: 'common',  // or 'organizations', 'consumers', specific GUID
  clientId: process.env.MICROSOFT_CLIENT_ID!,
  clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
  scopes: ['Mail.ReadWrite', 'Mail.Send'],
  redirectUri: 'https://example.com/oauth/callback',  // HTTPS required
  logger,
});

// Stateless middleware - token extracted from request
const mcpOAuthProvider = new McpOAuthProvider(mcpOAuthAdapter);
const middleware = mcpOAuthProvider.authMiddleware();
```

**Behavior**:
- Extracts token from `extra.authInfo.token` (MCP protocol)
- No server-side token storage (client manages tokens)
- Each request must include valid token
- Only works with HTTP transport (not stdio)
- **HTTPS required in production**

**Client Request Example**:
```typescript
const result = await client.callTool('outlook-message-search',
  { query: 'important' },
  {
    authInfo: {
      token: 'eyJ0eXAi...'  // Client-provided access token
    }
  }
);
```

**OAuth Endpoints Installed**:
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /oauth/authorize` - Start OAuth flow
- `POST /oauth/token` - Exchange code for token
- `POST /oauth/revoke` - Revoke token
- `POST /oauth/register` - Dynamic client registration

**Tenant Configuration**: Tenant set at adapter setup time, applies to all client authentications.

---

## Server-Level Middleware Architecture

### SOLID Principles Compliance

The middleware pattern follows SOLID principles for clean separation of concerns:

**1. Single Responsibility Principle (SRP)**:
- **Tools**: Define business operations (inputs, outputs, logic)
- **Middleware**: Handle authentication (token retrieval, error handling)
- **Server**: Coordinate integration (middleware application, registration)

**2. Open/Closed Principle (OCP)**:
- Adding new middleware (logging, metrics) requires only server changes
- Tools remain unchanged when adding cross-cutting concerns
```typescript
registerTools(mcpServer,
  tools
    .map(authMiddleware.withToolAuth)
    .map(toolMiddleware.withToolLogging)
    .map(metricsMiddleware.withToolMetrics)
);
```

**3. Dependency Inversion Principle (DIP)**:
- Tools don't depend on auth infrastructure
- High-level (business logic) doesn't depend on low-level (auth)
- Server mediates dependencies

**4. Inversion of Control (IoC)**:
- Server controls when/how middleware is applied
- Tools are passive (just define operations)
- Proper container pattern

### Tool Factory Pattern (No Middleware Knowledge)

Tools define pure business logic without auth dependencies:

```typescript
// Example tool implementation
import type { ToolModule } from '@mcp-z/server';
import type { EnrichedExtra } from '@mcp-z/oauth-microsoft';

const config = {
  name: 'outlook-message-get',
  description: 'Get an Outlook message by ID',
  inputSchema: {
    id: z.string().min(1).describe('Outlook message ID')
  },
  outputSchema: {
    result: z.discriminatedUnion('type', [
      z.object({ type: z.literal('success'), item: MessageSchema }),
      z.object({ type: z.literal('error'), error: z.string(), code: ErrorCodeSchema }),
    ])
  }
} as const;

async function handler(args: In, extra: EnrichedExtra): Promise<CallToolResult> {
  try {
    // extra.authContext.auth is guaranteed to exist (middleware ensures auth succeeded)
    const client = Client.initWithMiddleware({ authProvider: extra.authContext.auth });
    const message = await client.api(`/me/messages/${args.id}`).get();

    const result = {
      type: 'success' as const,
      item: message,
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
    };
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, `Error: ${message}`, {
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
}

// Tool factory has NO auth middleware parameter
export default function createTool(): ToolModule {
  return { name: 'outlook-message-get', config, handler };
}
```

**Key Points**:
- Tool imports `EnrichedExtra` type (provides IntelliSense)
- Handler receives guaranteed `authContext.auth` (middleware ensures this)
- Tool never imports auth providers or token stores
- No error handling for auth failures (middleware handles)

### Server Registration (Middleware Application)

Server applies middleware to business tools at registration time:

```typescript
// Example server implementation
import { LoopbackOAuthProvider } from '@mcp-z/oauth-microsoft';
import * as toolFactories from './mcp/tools/index.ts';

// Create loopback OAuth provider (configured at server startup)
const loopback = new LoopbackOAuthProvider({
  tokenStore,
  clientId: process.env.MICROSOFT_CLIENT_ID,
  tenantId: 'common',  // or 'organizations', 'consumers', or specific tenant GUID
  scopes: ['Mail.ReadWrite', 'Mail.Send'],
  logger,
});

// Create middleware based on deployment mode
const middleware = loopback.authMiddleware();

// Create business tools (no auth knowledge)
const tools = Object.values(toolFactories).map(factory => factory());

// Register with middleware
registerTools(mcpServer, tools.map(middleware.withToolAuth));  // Auth middleware applied
```

**Separation of Concerns**:
- Business tools get auth middleware (need Microsoft Graph client)
- Server decides middleware application strategy
- Middleware handles all auth concerns (token retrieval, refresh, errors)

### Error Handling Pattern

**Current Standard**: All errors use McpError from the MCP SDK.

**Tool Definition**:
```typescript
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

const config = {
  inputSchema: z.object({ id: z.string().min(1) }) as const,
  outputSchema: z.object({
    type: z.literal('success'),
    item: MessageSchema,
  }),
} as const;
```

**Handler Pattern**:
```typescript
type In = z.infer<typeof config.inputSchema>;
type Out = z.infer<typeof config.outputSchema>;

async function handler(args: In, extra: EnrichedExtra): Promise<CallToolResult> {
  try {
    const client = Client.initWithMiddleware({ authProvider: extra.authContext.auth });
    const message = await client.api(`/me/messages/${args.id}`).get();

    const result: Out = {
      type: 'success' as const,
      item: message,
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
    };
  } catch (error) {
    // Re-throw McpError as-is
    if (error instanceof McpError) {
      throw error;
    }

    // Wrap other errors in McpError
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, `Error: ${message}`, {
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
}
```

**Why This Works**:
- Handlers receive `EnrichedExtra` with guaranteed auth context
- Middleware catches auth errors BEFORE handler runs
- Handlers never execute if auth fails
- MCP SDK provides standard error types
- Type-safe: TypeScript enforces result matches schema

**Benefits**:
- MCP compliant - uses official SDK error types
- Simple - no helper function dependencies
- Explicit - clear, self-contained error handling
- Type safe - TypeScript enforces schema compliance

### EnrichedExtra Type

Middleware enriches request context with guaranteed auth:

```typescript
export interface EnrichedExtra extends RequestHandlerExtra {
  authContext: {
    auth: AuthenticationProvider;  // MSAL-compatible provider for Microsoft Graph
    accountId: string;              // Account being used
  };
  logger: Logger;                   // Injected logger
  _meta?: {
    accountId?: string;             // Backchannel account override (multi-account mode only)
  };
}
```

**Guarantee**: If handler runs, `authContext` exists. Middleware catches auth failures before handler execution.

**IntelliSense Benefits**:
- TypeScript autocomplete for `extra.authContext.auth`
- Compile-time errors if accessing non-existent properties
- Clear type documentation for tool developers

---

## Multi-Account Token Storage

### Storage Key Format

Compound keys enable O(1) direct lookups:

```
{accountId}:{service}:{type}
```

**Parameters**:
- `accountId`: **Email address** of the authenticated Microsoft account
- `service`: Service identifier (e.g., `'outlook'`)
- `type`: Token type suffix (e.g., `'token'`, `'refresh'`)

**Examples**:
```
user@outlook.com:outlook:token
work@company.com:outlook:token
personal@hotmail.com:outlook:token
```

**accountId Design**:
- **Always uses email address** fetched from Microsoft Graph API (`/me` endpoint)
- Never uses `'default'` fallback - email is mandatory
- Provides human-readable account identification
- Enables easy account selection and management
- Retrieved via `userPrincipalName` or `mail` field from Microsoft Graph

**Benefits**:
- Direct O(1) access without scanning
- Human-readable account identification (email addresses)
- Service-level isolation (Outlook independent from other services)
- Multi-account support via accountId
- Same email can have tokens for multiple services
- Different accounts can use same service
- Tenant information embedded in token (not in key)

### Storage Backends (Keyv Interface)

The library uses the `keyv` interface for swappable storage backends:

**Development (FileStore)**:
```typescript
import { KeyvFile } from 'keyv-file';
const tokenStore = new Keyv({
  store: new KeyvFile({ filename: '.tokens/microsoft.json' })
});
```

**Production (Redis)**:
```typescript
import KeyvRedis from '@keyv/redis';
const tokenStore = new Keyv({
  store: new KeyvRedis('redis://localhost:6379')
});
```

**Production (PostgreSQL)**:
```typescript
import KeyvPostgres from '@keyv/postgres';
const tokenStore = new Keyv({
  store: new KeyvPostgres('postgresql://localhost/mydb')
});
```

**Production (Encrypted DuckDB)**:
```typescript
import { DuckDBStore } from '@mcp-z/keyv-duckdb';
const tokenStore = new Keyv({
  store: new DuckDBStore('./store.duckdb', {
    encryptionKey: process.env.ENCRYPTION_KEY
  })
});
```

**Key Principle**: All backends implement the same `keyv` interface - change storage without changing auth code.

### Account Management Pattern

Users manage accounts via MCP tools:

- `outlook-account-current` - Show active account
- `outlook-account-list` - List all authorized accounts
- `outlook-account-switch` - Change active account
- `outlook-account-add` - Add new account via OAuth
- `outlook-account-remove` - Remove account and tokens

**Implementation**:
- Account tools access tokenStore directly (no middleware)
- Active account stored in config (`.tokens/config.json`)
- Service-level isolation (Outlook active independent of other services)
- Multi-tenantId: Per-user active account isolation

---

## Security Architecture

### PKCE (Proof Key for Code Exchange)

All OAuth flows use PKCE (RFC 7636) to prevent authorization code interception:

1. Client generates random `code_verifier`
2. Creates `code_challenge` = BASE64URL(SHA256(code_verifier))
3. Authorization request includes `code_challenge`
4. Token exchange requires original `code_verifier`
5. Microsoft validates SHA256(code_verifier) matches code_challenge

**Benefits**:
- Prevents authorization code interception attacks
- No client secret required for public clients
- Recommended by OAuth 2.1 for all clients
- Required by Microsoft identity platform for mobile/desktop apps

### Ephemeral Server (RFC 8252)

Loopback server implementation:

- Binds to `127.0.0.1` only (localhost isolation)
- OS-assigned ports (eliminates port conflicts)
- Server lifetime: OAuth flow duration only
- Single authorization code handled, then shutdown

**Redirect URI Pattern**:
```
http://127.0.0.1:{port}/callback
```

**Security**:
- No port conflicts across multiple OAuth instances
- Localhost-only (no network exposure)
- Temporary (not persistent server)

### Token Storage Security

**Responsibilities**:
- Implement encryption at rest in storage backend
- Use secure file permissions (FileStore)
- Use database access controls (Redis/PostgreSQL)
- Enable encryption for DuckDBStore (AES-256-GCM)

**Token Sanitization**:
- Tokens never logged (auto-sanitized from log output)
- Secrets redacted in error messages
- Stack traces scrubbed of sensitive data

**Keyv Backends Security**:
- FileStore: Use secure file permissions (`chmod 600`)
- Redis: Use authentication + TLS
- PostgreSQL: Use SSL connections + role-based access
- DuckDB: Enable AES-256-GCM encryption

### Tenant Isolation

**Security Consideration**: Tenant configuration affects authorization scope.

**Best Practices**:
- **Fixed-account deployments**: Use specific tenant GUID for maximum isolation
- **Multi-account scenarios**: Use `'common'` to allow flexibility, validate tenant in application logic if needed
- **Enterprise apps**: Use `'organizations'` to block personal accounts
- **Consumer apps**: Use `'consumers'` to block work accounts

**Token Security**:
- Tenant information embedded in MSAL tokens
- Token validation includes tenant check
- Cross-tenant token use prevented by Microsoft identity platform

### HTTPS Requirement for MCP OAuth

**CRITICAL**: MCP SDK OAuth **REQUIRES HTTPS in production**.

**Why**:
- Access tokens transmitted in HTTP headers (`Authorization: Bearer ...`)
- Plain HTTP exposes tokens to network interception
- Man-in-the-middle attacks can steal tokens

**When HTTPS is NOT Required**:
- Loopback OAuth (localhost 127.0.0.1 only)
- Development/testing on localhost
- Stdio transport (no network)

**When HTTPS IS Required**:
- MCP SDK OAuth on network-accessible servers
- Any production deployment accepting remote connections
- Multi-tenant SaaS applications

**Enforcement**:
- Server should reject HTTP requests with tokens in production
- Client must only send tokens over HTTPS
- Use reverse proxy (nginx, Caddy) for TLS termination if needed

---

## Migration Guide

### From Old Pattern (Pre-Middleware)

**Old Pattern** (tools have auth dependencies):
```typescript
async function handler(args, ctx) {
  const auth = await ctx.getAuth();  // Tool handles auth
  const client = Client.initWithMiddleware({ authProvider: auth });
  // business logic
}
```

**New Pattern** (middleware handles auth):
```typescript
async function handler(args, extra: EnrichedExtra) {
  // extra.authContext.auth guaranteed by middleware
  const client = Client.initWithMiddleware({ authProvider: extra.authContext.auth });
  // business logic only
}
```

**Why Breaking Change**:
- SRP: Tools shouldn't handle auth (cross-cutting concern)
- DIP: Tools shouldn't depend on auth infrastructure
- Testability: Tools easier to test without auth mocking
- Consistency: All tools use same auth pattern

**Migration Steps**:
1. Change handler signature: `(args, ctx)` → `(args, extra: EnrichedExtra)`
2. Remove `ctx.getAuth()` calls
3. Use `extra.authContext.auth` directly
4. Remove auth error handling from tools
5. Update tool factory to return `ToolModule` (no middleware param)
6. Let server apply middleware at registration

**No Backward Compatibility**: Old pattern not supported. Clean break for better architecture.

---

## Microsoft-Specific Considerations

### MSAL vs Google OAuth

**Key Differences**:
- Microsoft uses MSAL (Microsoft Authentication Library)
- Token format: JWT (JSON Web Tokens) vs Google's opaque tokens
- Tenant awareness: Microsoft requires tenant configuration
- Refresh token handling: MSAL manages refresh automatically
- Token validation: Microsoft provides built-in token validation

**API Client Pattern**:
```typescript
// Google (googleapis)
const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

// Microsoft (Microsoft Graph)
const client = Client.initWithMiddleware({ authProvider: msalAuthProvider });
const messages = await client.api('/me/messages').get();
```

### Tenant Configuration Guidelines

**Multi-Account Tools** (CLI, Desktop):
- Use `'common'` tenant
- Allows personal + work + school accounts
- Provides maximum flexibility

**Enterprise Applications**:
- Use `'organizations'` or specific tenant GUID
- Enforces corporate account policy
- Prevents personal account usage

**Consumer Applications**:
- Use `'consumers'` tenant
- Personal Microsoft accounts only
- Simplifies UX for consumers

**Security-Critical Applications**:
- Use specific tenant GUID
- Strongest isolation
- Recommended for fixed-account deployments

### Microsoft Graph API Compatibility

The auth provider returned by middleware is compatible with Microsoft Graph SDK v3:

```typescript
import { Client } from '@microsoft/microsoft-graph-client';

async function handler(args, extra: EnrichedExtra) {
  try {
    const client = Client.initWithMiddleware({
      authProvider: extra.authContext.auth
    });

    // Use Microsoft Graph API
    const messages = await client.api('/me/messages').get();
    const calendar = await client.api('/me/calendar/events').get();

    const result = {
      type: 'success' as const,
      data: { messages, calendar },
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
    };
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, `Error: ${message}`, {
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
}
```

---

## References

- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [MSAL.js Documentation](https://github.com/AzureAD/microsoft-authentication-library-for-js)
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/overview)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 - OAuth for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [MCP Specification](https://modelcontextprotocol.io/)
- [Keyv Storage Interface](https://github.com/jaredwray/keyv)
