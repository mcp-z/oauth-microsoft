# @mcp-z/oauth-microsoft

Docs: https://mcp-z.github.io/oauth-microsoft
OAuth client for Microsoft Graph with multi-account support and PKCE.

## Common uses

- Outlook OAuth in MCP servers
- CLI and desktop OAuth flows
- Device code auth for headless environments
- DCR (self-hosted) for shared HTTP servers

## Install

```bash
npm install @mcp-z/oauth-microsoft keyv
```

## Create a Microsoft app

1. Go to [Azure Portal](https://portal.azure.com/).
2. Navigate to Azure Active Directory > App registrations.
3. Click New registration.
4. Choose a name and select a supported account type.
5. Copy the Application (client) ID and Directory (tenant) ID.

## OAuth modes

### Loopback OAuth (interactive)

```ts
import { LoopbackOAuthProvider } from '@mcp-z/oauth-microsoft';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';

const provider = new LoopbackOAuthProvider({
  service: 'outlook',
  clientId: process.env.MS_CLIENT_ID!,
  tenantId: process.env.MS_TENANT_ID || 'common',
  scope: 'https://graph.microsoft.com/Mail.Read offline_access',
  tokenStore: new Keyv({ store: new KeyvFile({ filename: '.tokens/microsoft.json' }) })
});
```

### Device code (headless)

```ts
import { DeviceCodeProvider } from '@mcp-z/oauth-microsoft';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';

const provider = new DeviceCodeProvider({
  service: 'outlook',
  clientId: process.env.MS_CLIENT_ID!,
  tenantId: process.env.MS_TENANT_ID || 'common',
  scope: 'https://graph.microsoft.com/Mail.Read offline_access',
  tokenStore: new Keyv({ store: new KeyvFile({ filename: '.tokens/microsoft.json' }) })
});
```

### DCR (self-hosted)

Use `DcrOAuthProvider` for bearer validation and `createDcrRouter` to host the DCR endpoints.

```ts
import { DcrOAuthProvider, createDcrRouter } from '@mcp-z/oauth-microsoft';

const provider = new DcrOAuthProvider({
  clientId: process.env.MS_CLIENT_ID!,
  clientSecret: process.env.MS_CLIENT_SECRET!,
  scope: 'openid email profile',
  verifyEndpoint: 'https://your-host.com/oauth/verify'
});

const router = createDcrRouter({
  store,
  issuerUrl: 'https://your-host.com',
  baseUrl: 'https://your-host.com',
  scopesSupported: ['openid', 'email', 'profile'],
  clientConfig: {
    clientId: process.env.MS_CLIENT_ID!,
    clientSecret: process.env.MS_CLIENT_SECRET!
  }
});
```

## Config helpers

Use `parseConfig()` and `parseDcrConfig()` to load CLI + env settings for servers.

## Schemas and handler types

- `schemas` - Shared Zod schemas used by tools
- `EnrichedExtra` - Handler extra type with auth context

## Requirements

- Node.js >= 22
