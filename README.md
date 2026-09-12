# @mcp-z/oauth-microsoft

OAuth 2.0 client for Microsoft Graph with multi-account support, PKCE security, and swappable storage backends

## Common uses

- Outlook OAuth in MCP servers
- CLI and desktop OAuth flows
- Device code auth for headless environments
- CIMD and DCR (self-hosted) for shared HTTP servers

## Install

```bash
npm install @mcp-z/oauth-microsoft keyv keyv-file
```

## Create a Microsoft app

1. Go to [Azure Portal](https://portal.azure.com/).
2. Navigate to Azure Active Directory > App registrations.
3. Click New registration.
4. Choose a name and select a supported account type.
5. Copy the Application (client) ID and Directory (tenant) ID.
6. Select the credential platform that matches your deployment:
   - For a local stdio client, choose "Mobile and desktop applications" under Authentication and add the loopback redirect URI.
   - For an HTTP server, choose "Web" and add its public `/oauth/callback` URL. Local HTTP uses the port configured by the server.
   - For local hosting, add `http://localhost` for the [ephemeral redirect URL](https://en.wikipedia.org/wiki/Ephemeral_port).

## OAuth modes

### Redirect URI modes (loopback)
- No REDIRECT_URI: ephemeral loopback (random port), works for stdio and http.
- REDIRECT_URI set: persistent callback /oauth/callback (HTTP only).

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

const accessToken = await provider.getAccessToken();
// Opens the browser for consent when no valid token is stored, then returns a token.
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

const accessToken = await provider.getAccessToken();
// Prints a device code and verification URL for headless sign-in when needed.
```

### DCR (self-hosted)

Use `DcrOAuthProvider` for bearer validation and `createDcrRouter` to host the DCR endpoints and accept CIMD clients. CIMD resolution uses the secure shared resolver by default. A custom `cimdResolver` can be supplied for an explicit local-development policy; production deployments should additionally use an egress proxy.

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

For local development, configure the resolver explicitly with its loopback and HTTP opt-ins:

```ts
import { createCimdResolver } from '@mcp-z/oauth';
import { createDcrRouter } from '@mcp-z/oauth-microsoft';

const router = createDcrRouter({ ...config, cimdResolver: createCimdResolver({ allowHttpLoopback: true }) });
```

## Config helpers

Use `parseConfig()` and `parseDcrConfig()` to load CLI + env settings for servers.

## Schemas and handler types

- `schemas` - Shared Zod schemas used by tools
- `EnrichedExtra` - Handler extra type with auth context

## Requirements

- Node.js >= 18

## Documentation

[API Docs](https://mcp-z.github.io/oauth-microsoft)
