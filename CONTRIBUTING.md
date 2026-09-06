# Contributing to @mcp-z/oauth-microsoft

OAuth 2.0 client for Microsoft Graph with multi-account support, PKCE security, and swappable storage backends

## Before Starting

A few conventions here differ from what you might expect:

- **Breaking changes over compatibility.** This project has no compatibility burden yet. Do not add back-compat layers, migration utilities, or wrappers for deprecated APIs - change the API cleanly and bump the major.
- **Keep it approachable.** This is a small community project, not an enterprise codebase. Prefer the simplest solution that fits in the existing files over new abstractions, frameworks, or shared infrastructure.
- **Tests run against real services, not mocks.** Suites call live provider APIs with real credentials, so you need your own test account configured (see Test Setup below). A test that fails on credentials is reported, not skipped or loosened.
- **Test scratch goes in the package's gitignored `.tmp/`**, never `os.tmpdir()`.

## Branches

Two lines. `master` is the current major and where all new work goes; `support/1.x` maintains the 1.x line for consumers who have not migrated.

    master          2.x    current    the v2 MCP SDK, both protocol eras
    support/1.x     1.x    security fixes only, cut at v1.1.1

Check which one you are on before editing:

```bash
git rev-parse --abbrev-ref HEAD
```

Features, dependency migrations and API changes go to `master` only. A security fix that also affects 1.x is **cherry-picked** to `support/1.x` — never merge the branches into each other, in either direction.

This file is the 1.x line's guide too. It lives only on `master` so it cannot drift between the lines; from `support/1.x`, read it with `git show master:CONTRIBUTING.md`.

Releasing `support/1.x` carries one trap. `npm publish` moves `latest` to the highest version published, so a 1.x release made after 2.0.0 exists must name its dist-tag or every bare `npm install @mcp-z/oauth-microsoft` serves the old line:

```bash
npm publish --tag support-1
```

`prepublishOnly` refuses a bare publish from `support/1.x`, so forgetting the flag fails the publish rather than moving `latest`. `npm dist-tag add @mcp-z/oauth-microsoft@<version> latest` reverses a mistake at any time.

## Pre-Commit Commands

Install ts-dev-stack globally if not already installed:

```bash
npm install -g ts-dev-stack
```

Run before committing - this builds, type-checks, lints, and tests:

```bash
tsds validate
```

`tsds validate` also runs automatically on `npm publish` via the `prepublishOnly` hook; a failure blocks the publish.

## Testing

```bash
npm run test:setup    # Generate OAuth tokens (interactive, run once)
npm test              # Run the test suite
npm run test:engines  # Run the suite across every supported Node version
```

Specs live in `test/unit/`, mirroring `src/`. Cross-service specs live in `test/integration/`. Both run under `npm test`.

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

## Package Development

See `README.md` for package overview and usage.
