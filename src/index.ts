/**
 * @mcp-z/oauth-microsoft - Shared Microsoft OAuth implementation
 *
 * Provides OAuth authentication:
 * - Loopback OAuth (RFC 8252) - Server-managed, file-based tokens
 * - Device Code flow (RFC 8628) - For headless/limited-input scenarios
 */

export { createDcrRouter, type DcrRouterConfig } from './lib/dcr-router.ts';
export { type VerificationResult, verifyBearerToken } from './lib/dcr-verify.ts';
export { type AuthInfo, DcrTokenVerifier } from './lib/token-verifier.ts';
export { DcrOAuthProvider, type DcrOAuthProviderConfig } from './providers/dcr.ts';
export { type DeviceCodeConfig, DeviceCodeProvider } from './providers/device-code.ts';
export { LoopbackOAuthProvider } from './providers/loopback-oauth.ts';
export * as schemas from './schemas/index.ts';
export { createConfig, parseConfig, parseDcrConfig } from './setup/config.ts';
export * from './types.ts';
