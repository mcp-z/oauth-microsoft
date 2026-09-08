# Changelog

## [2.2.0] - 2026-09-07

### Added

- Self-hosted authorization servers now support Client ID Metadata Documents alongside Dynamic Client Registration. Public CIMD clients can complete authorization-code exchanges with PKCE and refresh-token exchanges without a client secret, while DCR clients retain their existing credential flow.

## [2.1.0] - 2026-09-07

### Added

- The authorization response now carries `iss` alongside `code` and `state` (RFC 9207), and `/.well-known/oauth-authorization-server` advertises `authorization_response_iss_parameter_supported: true`. A client that validates the issuer can now reject an authorization response minted by a different server.

### Changed

- PKCE is now required. `/oauth/authorize` rejects a request without `code_challenge` and `code_challenge_method=S256` with `invalid_request`, and the token endpoint verifies `code_verifier` unconditionally. Clients that omitted PKCE will fail to authorize from now on and must send an S256 challenge — a code minted without one has no proof of possession, so it is no longer issued or redeemable. The DCR flow in `@mcp-z/client` always sent S256 and is unaffected.

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
