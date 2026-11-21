# Changelog

## [2.4.5] - 2026-11-20

### Fixed

- A failed loopback sign-in now fails the waiting tool call at once with the real cause, instead of timing out after 5 minutes with "OAuth flow timed out". Without a configured `redirectUri` this covers a cancelled consent (the provider's `error` and `error_description`), a callback without a code, a callback without a state or with one that is not the sign-in's, a rejected code exchange, and a token store that cannot be written. With a configured `redirectUri` it covers only a rejected code exchange and a store failure; a cancelled consent, a callback without a code, and a callback without a state or with an unknown or mismatched state still wait the full 5 minutes.

## [2.4.4] - 2026-11-20

### Fixed

- Token and Graph requests made by the loopback, device-code and DCR providers, and the DCR verify request, keep their 30 second bound while the response body is read, so a server that sends headers and then stalls fails with `Request timeout after 30000ms` instead of holding the call open.
- `DeviceCodeProvider` logs at `info` instead of `debug` when the browser cannot be opened for the verification URL, so the failure is visible.

### Deprecated

- `DcrConfig.mode` and `DcrConfig.verifyUrl` are marked `@deprecated`: no mcp-z server reads them. They still parse and type-check as before.

## [2.4.3] - 2026-11-19

### Fixed

- A CIMD client that registers a loopback redirect such as `http://127.0.0.1/callback` can authorize with any port on it (RFC 8252 section 7.3), as registered clients already could. Other paths, hosts and `https` are still refused. Requires `@mcp-z/oauth` `^2.3.0`.
- `DcrTokenVerifier.verifyAccessToken` gives up after 30 seconds. A verify endpoint that never answers now fails the request (500 from the bearer gate) instead of holding it open. `verifyBearerToken` has the same bound.
- `DeviceCodeProvider` stops polling once the `expires_in` of the device code has passed and throws "Device code expired", even if Microsoft never answers `expired_token`.
- Verification failures from `verifyBearerToken` and `authMiddleware()` carry the authorization server's error description instead of the HTTP status.
- `DcrOAuthProvider.authMiddleware()` uses the provider tokens the bearer gate already verified and makes no second `/oauth/verify` request; without a gate it verifies through `DcrTokenVerifier`.

### Deprecated

- The `/mcp` presence check in `createDcrRouter` never runs in servers that mount `/mcp` before this router (all mcp-z servers) and verifies nothing. It is removed at the next major; use `bearerAuth` on `createHttpMcpRouter` or the SDK's `requireBearerAuth`.

## [2.4.2]

### Security

- The DCR router no longer serves `GET /debug/clients`, which returned every registered client with its secret to any caller. Anyone who ran a server with `--auth=dcr` reachable by others should treat registered client secrets as exposed.

## [2.4.1]

### Fixed

- The DCR token endpoint answers 400 `invalid_grant` (RFC 6749 section 5.2) when Microsoft rejects a stored refresh token as `invalid_grant`, so an MCP client discards its tokens and signs in again. Other refresh failures still answer 502.
- `DcrTokenVerifier.verifyAccessToken` and `verifyBearerToken` throw the MCP SDK's `OAuthError` (`invalid_token`) when `/oauth/verify` answers 401, so the SDK bearer middleware answers an expired or unknown token with 401 and a `WWW-Authenticate` challenge instead of 500. A verification outage still throws a plain `Error` (500).
- A store failure while saving a registered client answers 500 `server_error` instead of 400 `invalid_client_metadata`. Invalid metadata still answers 400.
- A failure to delete an abandoned sign-in's pending state no longer crashes the server with an unhandled rejection; it is logged as a warning.
- When a token refresh succeeds but saving the refreshed token fails, the storage error is thrown as itself instead of being reported as a failed refresh (`LoopbackOAuthProvider` and `DeviceCodeProvider`).

## [2.4.0]

### Changed

- Requires `@mcp-z/oauth` `^2.2.0`. The DCR storage helpers (`dcrUtils`) and the `RegisteredClient`, `AuthorizationCode` and `AccessToken` types now come from `@mcp-z/oauth`; this package re-exports the three types from `src/types.ts`.
- The `keyv` peer range is `^5.5.5 || ^6.1.0`: Keyv instances from either major work, and keys are not migrated between the two majors.

### Fixed

- DCR `listClients` (now in `@mcp-z/oauth`) returns only `dcr:client:` entries under every keyv version.

## [2.2.2] - 2026-09-20

### Fixed

- The setup and DCR configuration parsers now work on Node.js 18, the declared runtime minimum.
- Refresh flows now retain replacement provider refresh tokens and persist updated DCR credentials. Failed refreshes surface to callers instead of reusing stale tokens or starting an interactive flow in headless mode.

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
