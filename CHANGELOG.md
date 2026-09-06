# Changelog

## [1.1.2] - 2026-09-06

### Fixed

- An abandoned OAuth flow no longer keeps the host process alive. `startEphemeralOAuthFlow` starts an HTTP server for the callback and arms a 5-minute safety-net timer; neither was `unref`'d, so a flow that never completed — a headless caller, or a user who closes the browser — held an open socket and a live timer for up to five minutes. A running server stays alive on its own transport as before.

## [1.1.1] - 2026-09-05

### Fixed

- Rejects PKCE `plain`; only `S256` is accepted. CORS moved to an explicit allow-list.

## [1.1.0] - 2026-08-29

### Changed

- Dependency refresh; exports smoke tests added for the `.mjs`, `.cjs` and `.ts` entry points.

## [1.0.0] - 2025-12-28

Initial release.
