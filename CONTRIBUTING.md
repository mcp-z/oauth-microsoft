# Contributing to @mcp-z/oauth-microsoft

## Before Starting

**MUST READ**:
- [QUALITY.MD](QUALITY.md) - Quality principles (summarize before starting work)

## Pre-Commit Commands

Install ts-dev-stack globally if not already installed:
```bash
npm install -g ts-dev-stack
```

Run before committing:
```bash
tsds validate
```

## Test Setup

### Microsoft Azure App Configuration

All tests (including DCR integration tests) use a single Azure app registration. Microsoft requires a client secret for confidential clients (DCR tests):

1. Go to [Azure Portal App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Create or select an app registration
3. Under **Certificates & secrets**, create a client secret
4. Under **Authentication**, add redirect URIs as needed (e.g., `http://localhost:3000/oauth/callback`)

### Environment Variables

Copy `.env.test.example` to `.env.test` and configure:

```bash
MS_CLIENT_ID=your-client-id
MS_CLIENT_SECRET=your-client-secret
MS_TENANT_ID=common

# Enable manual OAuth tests (requires browser interaction)
TEST_INCLUDE_MANUAL=true
```

**Note**: `MS_CLIENT_SECRET` is required for DCR tests (Microsoft confidential clients require a secret for token exchange).

### Running Tests

```bash
npm run test:setup    # Generate OAuth tokens (interactive)
npm run test:unit     # Unit tests only
npm run test:integration  # Integration tests (some require browser)
npm test              # All tests
```

## Package Development

See package documentation:
- `README.md` - Package overview and usage
- `QUALITY.md` - Quality principles and standards
- `CLAUDE.md` - Development patterns and architecture guidance
