/**
 * Standalone types for Microsoft OAuth
 * No dependencies on other @mcp-z packages except @mcp-z/oauth
 */

// Import shared types from base @mcp-z/oauth package
// Public types (will be re-exported)
// Internal-only types (not re-exported, used by providers)
import type { AuthFlowDescriptor, CachedToken, DcrClientInformation, DcrClientMetadata, Logger, OAuth2TokenStorageProvider, ProviderTokens, ToolHandler, ToolModule, UserAuthProvider } from '@mcp-z/oauth';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Keyv } from 'keyv';

// Re-export only essential shared types for public API
export type { Logger, CachedToken, ToolModule, ProviderTokens, DcrClientMetadata, DcrClientInformation };

// Re-export error class
export { AuthRequiredError } from '@mcp-z/oauth';

// Make internal types available for internal use without exporting
export type { ToolHandler, AuthFlowDescriptor, OAuth2TokenStorageProvider, UserAuthProvider, RequestHandlerExtra, ServerRequest, ServerNotification };

// ============================================================================
// Core Authentication Types
// ============================================================================

/**
 * Microsoft service types that support OAuth
 * OAuth clients support all Microsoft services provided by Microsoft Graph
 * @public
 */
export type MicrosoftService = string;

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * OAuth client configuration for upstream provider
 * @public
 */
export interface OAuthClientConfig {
  /** OAuth client ID for upstream provider */
  clientId: string;
  /** OAuth client secret (optional for some flows) */
  clientSecret?: string;
  /** Tenant/directory ID (for multi-tenant providers) */
  tenantId?: string;
}

/**
 * Microsoft OAuth configuration interface.
 * Contains all OAuth-related configuration from CLI arguments and environment variables.
 * @public
 */
export interface OAuthConfig {
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret (optional for public clients) */
  clientSecret?: string;
  /** Azure AD tenant ID */
  tenantId: string;
  /** OAuth adapter mode */
  auth: 'loopback-oauth' | 'device-code' | 'dcr';
  /** Whether to run in headless mode (no browser interaction) */
  headless: boolean;
  /** Optional redirect URI override (defaults to ephemeral loopback) */
  redirectUri?: string;
}

/**
 * DCR configuration for dynamic client registration
 * @public
 */
export interface DcrConfig {
  /** DCR mode: self-hosted (runs own OAuth server) or external (uses Auth0/Stitch) */
  mode: 'self-hosted' | 'external';
  /** External verification endpoint URL (required for external mode) */
  verifyUrl?: string;
  /** DCR client storage URI (required for self-hosted mode) */
  storeUri?: string;
  /** OAuth client ID for Microsoft Graph */
  clientId: string;
  /** OAuth client secret (optional for public clients) */
  clientSecret?: string;
  /** Azure AD tenant ID */
  tenantId: string;
  /** OAuth scopes to request */
  scope: string;
  /** Logger instance */
  logger?: Logger;
}

/**
 * Configuration for loopback OAuth client
 * @public
 */
export interface LoopbackOAuthConfig {
  /** Microsoft service type (e.g., 'outlook') */
  service: MicrosoftService;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret (optional for public clients) */
  clientSecret?: string | undefined;
  /** Azure AD tenant ID */
  tenantId: string;
  /** OAuth scopes to request */
  scope: string;
  /** Whether to run in headless mode (no browser interaction) */
  headless: boolean;
  /** Logger instance */
  logger: Logger;
  /** Token storage */
  tokenStore: Keyv<unknown>;
  /** Optional redirect URI override (defaults to ephemeral loopback) */
  redirectUri?: string;
}

// ============================================================================
// Middleware Types
// ============================================================================

/**
 * Microsoft Graph AuthenticationProvider interface
 * Used by Microsoft Graph SDK for API authentication
 * @public
 */
export interface MicrosoftAuthProvider {
  getAccessToken: () => Promise<string>;
}

/**
 * Auth context injected into extra by middleware
 * @public
 */
export interface AuthContext {
  /**
   * Microsoft Graph AuthenticationProvider ready for Graph SDK
   * GUARANTEED to exist when handler runs
   */
  auth: MicrosoftAuthProvider;

  /**
   * Account being used (for logging, debugging)
   */
  accountId: string;

  /**
   * User ID (multi-tenant only)
   */
}

/**
 * Enriched extra with guaranteed auth context and logger
 * Handlers receive this type - never plain RequestHandlerExtra
 * @public
 */
export interface EnrichedExtra extends RequestHandlerExtra<ServerRequest, ServerNotification> {
  /**
   * Auth context injected by middleware
   * GUARANTEED to exist (middleware catches auth failures)
   */
  authContext: AuthContext;

  /**
   * Logger injected by middleware
   * GUARANTEED to exist
   */
  logger: Logger;

  /**
   * HTTP request object (for HTTP transport scenarios)
   * Optional - present when using HTTP transport with JWT/session auth
   */
  req?: unknown;

  // Preserve backchannel support
  _meta?: {
    accountId?: string;
    [key: string]: unknown;
  };
}

// ============================================================================
// DCR Internal Types
// ============================================================================

/**
 * Registered client with full metadata
 * Extends DcrClientInformation with internal timestamps
 * @internal
 */
export interface RegisteredClient extends DcrClientInformation {
  /** Creation timestamp (milliseconds since epoch) */
  created_at: number;
}

/**
 * Authorization code data structure
 * @public
 */
export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge?: string;
  code_challenge_method?: string;
  /** Microsoft provider tokens obtained during authorization */
  providerTokens: ProviderTokens;
  created_at: number;
  expires_at: number;
}

/**
 * Access token data structure
 * @public
 */
export interface AccessToken {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  client_id: string;
  /** Microsoft provider tokens */
  providerTokens: ProviderTokens;
  created_at: number;
}

// ============================================================================
// Schema Types
// ============================================================================

/**
 * Auth required response interface
 * Re-exported from @mcp-z/oauth for consistency
 */
export type { AuthRequired, AuthRequiredBranch } from './schemas/index.ts';
