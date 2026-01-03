/**
 * Microsoft OAuth configuration parsing from CLI arguments and environment variables.
 *
 * This module provides utilities to parse Microsoft OAuth configuration from
 * CLI arguments and environment variables, following the same pattern as @mcp-z/server's
 * parseConfig().
 */

import { parseArgs } from 'util';
import type { DcrConfig, OAuthConfig } from '../types.ts';

// Re-export for external use
export type { DcrConfig, OAuthConfig };

/**
 * Auth mode type (from OAuthConfig)
 */
type AuthMode = 'loopback-oauth' | 'device-code' | 'dcr';

/**
 * Parse OAuth mode string into auth mode.
 *
 * @param value - OAuth mode string ('loopback-oauth', 'device-code', or 'dcr')
 * @returns Parsed auth mode
 * @throws Error if value is invalid
 *
 * @example Valid formats
 * ```typescript
 * parseAuthMode('loopback-oauth')   // { auth: 'loopback-oauth' }
 * parseAuthMode('device-code')      // { auth: 'device-code' }
 * parseAuthMode('dcr')              // { auth: 'dcr' }
 * ```
 */
function parseAuthMode(value: string): {
  auth: AuthMode;
} {
  // Validate auth mode
  if (value !== 'loopback-oauth' && value !== 'device-code' && value !== 'dcr') {
    throw new Error(`Invalid --auth value: "${value}". Valid values: loopback-oauth, device-code, dcr`);
  }

  return {
    auth: value as AuthMode,
  };
}

/**
 * Transport type for MCP servers
 *
 * - 'stdio': Standard input/output transport
 * - 'http': HTTP transport
 */
export type TransportType = 'stdio' | 'http';

/**
 * Parse Microsoft OAuth configuration from CLI arguments and environment variables.
 *
 * CLI Arguments:
 * - --auth: OAuth mode ('loopback-oauth' | 'device-code' | 'dcr')
 *   - Default: 'loopback-oauth' (if flag is omitted)
 * - --headless: Disable browser opening for OAuth flow (default: false, true in test env)
 * - --redirect-uri: Override OAuth redirect URI (default: ephemeral loopback)
 * - --tenant-id: Override Microsoft tenant ID
 *
 * Required environment variables:
 * - MS_CLIENT_ID: Azure AD application (client) ID
 * - MS_TENANT_ID: Azure AD tenant ID ('common', 'organizations', 'consumers', or tenant GUID)
 *
 * Optional environment variables:
 * - MS_CLIENT_SECRET: Azure AD client secret (optional for public clients)
 * - AUTH_MODE: OAuth mode (same format as --auth flag)
 * - HEADLESS: Headless mode flag ('true' to enable)
 * - REDIRECT_URI: OAuth redirect URI (overridden by --redirect-uri CLI flag)
 *
 * @param args - CLI arguments array (typically process.argv)
 * @param env - Environment variables object (typically process.env)
 * @param transport - Optional transport type. If 'stdio' and auth mode is 'dcr', throws an error.
 * @returns Parsed Microsoft OAuth configuration
 * @throws Error if required environment variables are missing, values are invalid, or DCR is used with stdio transport
 *
 * @example Default mode (no flags)
 * ```typescript
 * const config = parseConfig(process.argv, process.env);
 * // { auth: 'loopback-oauth' }
 * ```
 *
 * @example Override auth mode
 * ```typescript
 * parseConfig(['--auth=loopback-oauth'], process.env);
 * parseConfig(['--auth=device-code'], process.env);
 * ```
 *
 * @example With transport validation
 * ```typescript
 * parseConfig(['--auth=dcr'], process.env, 'http'); // OK
 * parseConfig(['--auth=dcr'], process.env, 'stdio'); // Throws error
 * ```
 *
 * Valid auth modes:
 * - loopback-oauth (default)
 * - device-code
 * - dcr (HTTP transport only)
 */
export function parseConfig(args: string[], env: Record<string, string | undefined>, transport?: TransportType): OAuthConfig {
  function requiredEnv(key: string): string {
    const value = env[key];
    if (!value) {
      throw new Error(`Environment variable ${key} is required for Microsoft OAuth`);
    }
    return value;
  }

  // Parse CLI arguments
  const { values } = parseArgs({
    args,
    options: {
      auth: { type: 'string' },
      headless: { type: 'boolean' },
      'redirect-uri': { type: 'string' },
      'tenant-id': { type: 'string' },
    },
    strict: false, // Allow other arguments
    allowPositionals: true,
  });

  // Parse OAuth mode
  const authArg = typeof values.auth === 'string' ? values.auth : undefined;
  const envAuthMode = env.AUTH_MODE;
  const mode = authArg || envAuthMode;

  let auth: AuthMode;

  if (mode) {
    const parsed = parseAuthMode(mode);
    auth = parsed.auth;
  } else {
    // DEFAULT: No flags provided, use loopback-oauth
    auth = 'loopback-oauth';
  }

  // Validate: DCR only works with HTTP transport
  if (auth === 'dcr' && transport === 'stdio') {
    throw new Error('DCR authentication mode requires HTTP transport. DCR is not supported with stdio transport.');
  }

  // Parse redirect-uri (CLI overrides ENV)
  const cliRedirectUri = typeof values['redirect-uri'] === 'string' ? values['redirect-uri'] : undefined;
  const envRedirectUri = env.REDIRECT_URI;
  const redirectUri = cliRedirectUri ?? envRedirectUri;
  if (redirectUri && transport === 'stdio') {
    throw new Error('REDIRECT_URI requires HTTP transport. The OAuth callback must be served over HTTP.');
  }

  // Parse headless mode
  if (typeof values.headless === 'string') throw new Error('Use --headless or --no-headless (do not pass a value)');
  const cliHeadless = values['no-headless'] ? false : values.headless === true ? true : undefined;
  const envHeadless = env.HEADLESS === 'true' ? true : env.HEADLESS === 'false' ? false : undefined;
  const headless = cliHeadless ?? envHeadless ?? redirectUri !== undefined;

  // Parse tenant-id (CLI overrides environment)
  const cliTenantId = typeof values['tenant-id'] === 'string' ? values['tenant-id'] : undefined;
  const tenantId = cliTenantId ?? requiredEnv('MS_TENANT_ID');

  // Parse credentials
  const clientId = requiredEnv('MS_CLIENT_ID');
  const clientSecret = env.MS_CLIENT_SECRET;

  return {
    clientId,
    tenantId,
    ...(clientSecret && { clientSecret }),
    auth,
    headless,
    ...(redirectUri && { redirectUri }),
  };
}

/**
 * Build production configuration from process globals.
 * Entry point for production server.
 */
export function createConfig(): OAuthConfig {
  return parseConfig(process.argv, process.env);
}

/**
 * Parse DCR configuration from CLI arguments and environment variables.
 *
 * CLI Arguments:
 * - --dcr-mode: DCR mode ('self-hosted' | 'external')
 *   - Default: 'self-hosted' (if flag is omitted)
 * - --dcr-verify-url: External verification endpoint URL (required for external mode)
 * - --dcr-store-uri: DCR client storage URI (required for self-hosted mode)
 * - --tenant-id: Override Microsoft tenant ID
 *
 * Required environment variables:
 * - MS_CLIENT_ID: Azure AD application (client) ID
 * - MS_TENANT_ID: Azure AD tenant ID ('common', 'organizations', 'consumers', or tenant GUID)
 *
 * Optional environment variables:
 * - MS_CLIENT_SECRET: Azure AD client secret (optional for public clients)
 * - DCR_MODE: DCR mode (same format as --dcr-mode flag)
 * - DCR_VERIFY_URL: External verification URL (same as --dcr-verify-url flag)
 * - DCR_STORE_URI: DCR storage URI (same as --dcr-store-uri flag)
 *
 * @param args - CLI arguments array (typically process.argv)
 * @param env - Environment variables object (typically process.env)
 * @param scope - OAuth scopes to request (space-separated)
 * @returns Parsed DCR configuration
 * @throws Error if required environment variables are missing or validation fails
 *
 * @example Self-hosted mode
 * ```typescript
 * const config = parseDcrConfig(
 *   ['--dcr-mode=self-hosted', '--dcr-store-uri=file:///path/to/store.json'],
 *   process.env,
 *   'https://graph.microsoft.com/.default'
 * );
 * ```
 *
 * @example External mode
 * ```typescript
 * const config = parseDcrConfig(
 *   ['--dcr-mode=external', '--dcr-verify-url=https://auth0.example.com/verify'],
 *   process.env,
 *   'https://graph.microsoft.com/.default'
 * );
 * ```
 */
export function parseDcrConfig(args: string[], env: Record<string, string | undefined>, scope: string): DcrConfig {
  function requiredEnv(key: string): string {
    const value = env[key];
    if (!value) {
      throw new Error(`Environment variable ${key} is required for DCR configuration`);
    }
    return value;
  }

  // Parse CLI arguments
  const { values } = parseArgs({
    args,
    options: {
      'dcr-mode': { type: 'string' },
      'dcr-verify-url': { type: 'string' },
      'dcr-store-uri': { type: 'string' },
      'tenant-id': { type: 'string' },
    },
    strict: false, // Allow other arguments
    allowPositionals: true,
  });

  // Parse DCR mode (CLI overrides environment)
  const cliMode = typeof values['dcr-mode'] === 'string' ? values['dcr-mode'] : undefined;
  const envMode = env.DCR_MODE;
  const mode = cliMode || envMode || 'self-hosted';

  // Validate DCR mode
  if (mode !== 'self-hosted' && mode !== 'external') {
    throw new Error(`Invalid --dcr-mode value: "${mode}". Valid values: self-hosted, external`);
  }

  // Parse verify URL (CLI overrides environment)
  const cliVerifyUrl = typeof values['dcr-verify-url'] === 'string' ? values['dcr-verify-url'] : undefined;
  const envVerifyUrl = env.DCR_VERIFY_URL;
  const verifyUrl = cliVerifyUrl || envVerifyUrl;

  // Parse store URI (CLI overrides environment)
  const cliStoreUri = typeof values['dcr-store-uri'] === 'string' ? values['dcr-store-uri'] : undefined;
  const envStoreUri = env.DCR_STORE_URI;
  const storeUri = cliStoreUri || envStoreUri;

  // Validate mode-specific required fields
  if (mode === 'external' && !verifyUrl) {
    throw new Error('DCR external mode requires --dcr-verify-url or DCR_VERIFY_URL environment variable');
  }

  // Parse tenant-id (CLI overrides environment)
  const cliTenantId = typeof values['tenant-id'] === 'string' ? values['tenant-id'] : undefined;
  const tenantId = cliTenantId ?? requiredEnv('MS_TENANT_ID');

  // Parse credentials
  const clientId = requiredEnv('MS_CLIENT_ID');
  const clientSecret = env.MS_CLIENT_SECRET;

  return {
    mode,
    ...(verifyUrl && { verifyUrl }),
    ...(storeUri && { storeUri }),
    clientId,
    ...(clientSecret && { clientSecret }),
    tenantId,
    scope,
  };
}
