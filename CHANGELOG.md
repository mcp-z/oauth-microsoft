# Changelog

## [2.0.2] - 2026-09-07

### Fixed

- The RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource` named `baseUrl` as the `resource`, while the document at `/.well-known/oauth-protected-resource/mcp` named `${baseUrl}/mcp`. Two documents describing one protected resource gave it two different identifiers, and the root one named the deployment root — which is not a protected resource. A client that read it would audience-bind its token (RFC 8707) to the wrong identifier. Both documents now name the MCP endpoint.

## [2.0.1] - 2026-09-06

### Fixed

- An abandoned interactive OAuth flow no longer keeps the host process alive. The loopback callback server and its five-minute timeout are now unreferenced, so a headless caller that never completes the flow, or a user who closes the browser, does not hold the process open waiting.

## [2.0.0] - 2026-09-06

### Changed

- Migrated to the v2 MCP SDK. `McpError`/`ErrorCode` are `ProtocolError`/`ProtocolErrorCode`, reached through `@mcp-z/server`; wire codes are unchanged.
- The 1.x line is maintained on `support/1.x` and published under the `support-1` dist-tag.

## [1.1.1] - 2026-09-05

### Fixed

- Rejects PKCE `plain`; only `S256` is accepted. CORS moved to an explicit allow-list.

## [1.1.0] - 2026-08-29

### Changed

- Dependency refresh; exports smoke tests added for the `.mjs`, `.cjs` and `.ts` entry points.

## [1.0.0] - 2025-12-28

Initial release.
