/**
 * DCR Router - OAuth 2.0 Authorization Server
 *
 * Implements OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * and OAuth 2.0 Authorization Server endpoints (RFC 6749, RFC 8414, RFC 9728).
 *
 * Endpoints:
 * - GET /.well-known/oauth-authorization-server (RFC 8414 metadata)
 * - GET /.well-known/oauth-protected-resource (RFC 9728 metadata - root)
 * - GET /.well-known/oauth-protected-resource/mcp (RFC 9728 metadata - sub-path)
 * - POST /oauth/register (RFC 7591 client registration)
 * - GET /oauth/authorize (RFC 6749 authorization endpoint)
 * - POST /oauth/token (RFC 6749 token endpoint)
 * - POST /oauth/revoke (RFC 7009 token revocation)
 * - GET /oauth/verify (token verification for Resource Server)
 */

import type { ProviderTokens, RFC8414Metadata, RFC9728Metadata } from '@mcp-z/oauth';
import { createHash, randomUUID } from 'crypto';
import type { Request, Response } from 'express';
import express from 'express';
import type { Keyv } from 'keyv';
import { DcrOAuthProvider } from '../providers/dcr.ts';
import type { AccessToken, AuthorizationCode, OAuthClientConfig } from '../types.ts';
import * as dcrUtils from './dcr-utils.ts';

/**
 * Configuration for DCR Router (self-hosted mode only)
 */
export interface DcrRouterConfig {
  /** Single Keyv store for all DCR data */
  store: Keyv;

  /** Authorization Server issuer URL */
  issuerUrl: string;

  /** Base URL for OAuth endpoints */
  baseUrl: string;

  /** Supported OAuth scopes */
  scopesSupported: string[];

  /** OAuth client configuration for upstream provider */
  clientConfig: OAuthClientConfig;
}

/**
 * Create DCR Router with OAuth 2.0 endpoints (self-hosted mode)
 *
 * For external mode (Auth0/Stitch), don't call this function - no router needed.
 * The server code should check DcrConfig.mode and only call this for 'self-hosted'.
 *
 * @param config - Router configuration
 * @returns Express router with OAuth endpoints
 */
export function createDcrRouter(config: DcrRouterConfig): express.Router {
  const router = express.Router();
  const { store, issuerUrl, baseUrl, scopesSupported, clientConfig } = config;

  // Apply required middleware for OAuth 2.0 endpoints (RFC 6749)
  router.use(express.json()); // For /oauth/register (application/json)
  router.use(express.urlencoded({ extended: true })); // For /oauth/token (application/x-www-form-urlencoded)

  /**
   * OAuth Authorization Server Metadata (RFC 8414)
   * GET /.well-known/oauth-authorization-server
   */
  router.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
    const metadata: RFC8414Metadata = {
      issuer: issuerUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      scopes_supported: scopesSupported,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256', 'plain'],
      service_documentation: `${baseUrl}/docs`,
    };
    res.json(metadata);
  });

  /**
   * OAuth Protected Resource Metadata (RFC 9728 - Root)
   * GET /.well-known/oauth-protected-resource
   */
  router.get('/.well-known/oauth-protected-resource', (_req: Request, res: Response) => {
    const metadata: RFC9728Metadata = {
      resource: baseUrl,
      authorization_servers: [baseUrl],
      scopes_supported: scopesSupported,
      bearer_methods_supported: ['header'],
    };
    res.json(metadata);
  });

  /**
   * OAuth Protected Resource Metadata (RFC 9728 - Sub-path /mcp)
   * GET /.well-known/oauth-protected-resource/mcp
   */
  router.get('/.well-known/oauth-protected-resource/mcp', (_req: Request, res: Response) => {
    const metadata: RFC9728Metadata = {
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      scopes_supported: scopesSupported,
      bearer_methods_supported: ['header'],
    };
    res.json(metadata);
  });

  /**
   * Dynamic Client Registration (RFC 7591)
   * POST /oauth/register
   */
  router.post('/oauth/register', async (req: Request, res: Response) => {
    try {
      const registrationRequest = req.body;

      // Register the client
      const client = await dcrUtils.registerClient(store, registrationRequest);

      // Return client information (RFC 7591 Section 3.2.1)
      res.status(201).json(client);
    } catch (error) {
      res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: error instanceof Error ? error.message : 'Invalid registration request',
      });
    }
  });

  /**
   * OAuth Authorization Endpoint (RFC 6749 Section 3.1)
   * GET /oauth/authorize
   *
   * Initiates Microsoft OAuth flow, then generates DCR authorization code
   */
  router.get('/oauth/authorize', async (req: Request, res: Response) => {
    const { response_type, client_id, redirect_uri, scope = '', state = '', code_challenge, code_challenge_method } = req.query;

    // Validate required parameters
    if (response_type !== 'code') {
      return res.status(400).json({
        error: 'unsupported_response_type',
        error_description: 'Only response_type=code is supported',
      });
    }

    if (!client_id || typeof client_id !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'client_id is required',
      });
    }

    if (!redirect_uri || typeof redirect_uri !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri is required',
      });
    }

    // Validate client
    const client = await dcrUtils.getClient(store, client_id);
    if (!client) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Unknown client_id',
      });
    }

    // Validate redirect_uri
    const isValidRedirect = await dcrUtils.validateRedirectUri(store, client_id, redirect_uri);
    if (!isValidRedirect) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect_uri',
      });
    }

    // Store DCR request state for Microsoft OAuth callback
    const msState = randomUUID();
    const dcrRequestState = {
      client_id,
      redirect_uri,
      scope: typeof scope === 'string' ? scope : '',
      state: typeof state === 'string' ? state : undefined,
      code_challenge: typeof code_challenge === 'string' ? code_challenge : undefined,
      code_challenge_method: typeof code_challenge_method === 'string' ? code_challenge_method : undefined,
      created_at: Date.now(),
      expires_at: Date.now() + 600000, // 10 minutes
    };

    await store.set(`dcr:ms-state:${msState}`, dcrRequestState, 600000); // 10 min TTL

    // Build Microsoft authorization URL
    const msAuthUrl = new URL(`https://login.microsoftonline.com/${clientConfig.tenantId || 'common'}/oauth2/v2.0/authorize`);
    msAuthUrl.searchParams.set('client_id', clientConfig.clientId);
    msAuthUrl.searchParams.set('response_type', 'code');
    msAuthUrl.searchParams.set('redirect_uri', `${baseUrl}/oauth/callback`);
    msAuthUrl.searchParams.set('scope', typeof scope === 'string' ? scope : '');
    msAuthUrl.searchParams.set('state', msState);
    msAuthUrl.searchParams.set('response_mode', 'query');

    // Redirect user to Microsoft for authorization
    return res.redirect(msAuthUrl.toString());
  });

  /**
   * OAuth Callback Handler
   * GET /oauth/callback
   *
   * Handles callback from Microsoft after user authorization
   */
  router.get('/oauth/callback', async (req: Request, res: Response) => {
    const { code: msCode, state: msState, error, error_description } = req.query;

    // Handle Microsoft OAuth errors
    if (error) {
      return res.status(400).json({
        error,
        error_description: error_description || 'Microsoft OAuth authorization failed',
      });
    }

    if (!msCode || typeof msCode !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Authorization code is required',
      });
    }

    if (!msState || typeof msState !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'State parameter is required',
      });
    }

    // Retrieve original DCR request state
    const dcrRequestState = await store.get(`dcr:ms-state:${msState}`);
    if (!dcrRequestState) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid or expired state parameter',
      });
    }

    // Delete state (one-time use)
    await store.delete(`dcr:ms-state:${msState}`);

    // Exchange Microsoft authorization code for tokens
    try {
      const tokenUrl = `https://login.microsoftonline.com/${clientConfig.tenantId || 'common'}/oauth2/v2.0/token`;
      const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code: msCode,
        client_id: clientConfig.clientId,
        redirect_uri: `${baseUrl}/oauth/callback`,
        scope: dcrRequestState.scope,
      });

      // Add client_secret if available (confidential client)
      if (clientConfig.clientSecret) {
        tokenParams.set('client_secret', clientConfig.clientSecret);
      }

      const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: tokenParams.toString(),
      });

      if (!tokenResponse.ok) {
        const errorData = (await tokenResponse.json()) as { error?: string; error_description?: string };
        throw new Error(`Microsoft token exchange failed: ${errorData.error_description || errorData.error}`);
      }

      const tokenData = (await tokenResponse.json()) as {
        access_token: string;
        refresh_token?: string;
        expires_in: number;
        scope: string;
      };

      // Create provider tokens from Microsoft response
      const providerTokens: ProviderTokens = {
        accessToken: tokenData.access_token,
        ...(tokenData.refresh_token && { refreshToken: tokenData.refresh_token }),
        expiresAt: Date.now() + tokenData.expires_in * 1000,
        scope: tokenData.scope,
      };

      // Generate DCR authorization code with real provider tokens
      const dcrCode = randomUUID();
      const authCode: AuthorizationCode = {
        code: dcrCode,
        client_id: dcrRequestState.client_id,
        redirect_uri: dcrRequestState.redirect_uri,
        scope: dcrRequestState.scope,
        ...(dcrRequestState.code_challenge && { code_challenge: dcrRequestState.code_challenge }),
        ...(dcrRequestState.code_challenge_method && { code_challenge_method: dcrRequestState.code_challenge_method }),
        providerTokens,
        created_at: Date.now(),
        expires_at: Date.now() + 600000, // 10 minutes
      };

      await dcrUtils.setAuthCode(store, dcrCode, authCode);

      // Redirect back to MCP client with DCR authorization code
      const clientRedirectUrl = new URL(dcrRequestState.redirect_uri);
      clientRedirectUrl.searchParams.set('code', dcrCode);
      if (dcrRequestState.state) {
        clientRedirectUrl.searchParams.set('state', dcrRequestState.state);
      }

      return res.redirect(clientRedirectUrl.toString());
    } catch (error) {
      return res.status(500).json({
        error: 'server_error',
        error_description: error instanceof Error ? error.message : 'Failed to exchange authorization code',
      });
    }
  });

  /**
   * OAuth Token Endpoint (RFC 6749 Section 3.2)
   * POST /oauth/token
   */
  router.post('/oauth/token', async (req: Request, res: Response) => {
    // Extract client credentials from either body or Basic Auth header
    let client_id = req.body.client_id;
    let client_secret = req.body.client_secret;

    // Support client_secret_basic authentication (RFC 6749 Section 2.3.1)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      const base64Credentials = authHeader.substring(6);
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      const [id, secret] = credentials.split(':');
      client_id = id;
      client_secret = secret;
    }

    const { grant_type, code, redirect_uri, refresh_token, code_verifier } = req.body;

    // Validate grant_type
    if (!grant_type) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'grant_type is required',
      });
    }

    if (grant_type === 'authorization_code') {
      // Authorization Code Grant
      if (!code || !client_id || !redirect_uri) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'code, client_id, and redirect_uri are required',
        });
      }

      // Validate client credentials
      const isValidClient = await dcrUtils.validateClient(store, client_id, client_secret ?? '');
      if (!isValidClient) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
      }

      // Get authorization code
      const authCode = await dcrUtils.getAuthCode(store, code);
      if (!authCode) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired authorization code',
        });
      }

      // Validate authorization code
      if (authCode.client_id !== client_id || authCode.redirect_uri !== redirect_uri) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code mismatch',
        });
      }

      if (Date.now() > authCode.expires_at) {
        await dcrUtils.deleteAuthCode(store, code);
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code expired',
        });
      }

      // Validate PKCE if used
      if (authCode.code_challenge) {
        if (!code_verifier) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'code_verifier is required for PKCE',
          });
        }

        // Validate code_verifier against code_challenge
        const method = authCode.code_challenge_method ?? 'plain';
        const computedChallenge = method === 'S256' ? createHash('sha256').update(code_verifier).digest('base64url') : code_verifier;

        if (computedChallenge !== authCode.code_challenge) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid code_verifier',
          });
        }
      }

      // Delete authorization code (one-time use)
      await dcrUtils.deleteAuthCode(store, code);

      // Generate DCR access token
      const accessToken = randomUUID();
      const refreshTokenValue = randomUUID();

      const tokenData: AccessToken = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshTokenValue,
        scope: authCode.scope,
        client_id,
        providerTokens: authCode.providerTokens,
        created_at: Date.now(),
      };

      await dcrUtils.setAccessToken(store, accessToken, tokenData);
      await dcrUtils.setRefreshToken(store, refreshTokenValue, tokenData);

      // Store provider tokens indexed by DCR access token
      await dcrUtils.setProviderTokens(store, accessToken, authCode.providerTokens);

      // Return token response
      return res.json({
        access_token: tokenData.access_token,
        token_type: tokenData.token_type,
        expires_in: tokenData.expires_in,
        refresh_token: tokenData.refresh_token,
        scope: tokenData.scope,
      });
    }
    if (grant_type === 'refresh_token') {
      // Refresh Token Grant
      if (!refresh_token || !client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'refresh_token and client_id are required',
        });
      }

      // Validate client credentials
      const isValidClient = await dcrUtils.validateClient(store, client_id, client_secret ?? '');
      if (!isValidClient) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
      }

      // Get refresh token
      const tokenData = await dcrUtils.getRefreshToken(store, refresh_token);
      if (!tokenData || tokenData.client_id !== client_id) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid refresh token',
        });
      }

      // Refresh provider tokens if available
      let refreshedProviderTokens = tokenData.providerTokens;
      if (tokenData.providerTokens.refreshToken) {
        try {
          // Create DcrOAuthProvider instance to refresh Microsoft tokens
          const provider = new DcrOAuthProvider({
            clientId: clientConfig.clientId,
            ...(clientConfig.clientSecret && { clientSecret: clientConfig.clientSecret }),
            tenantId: clientConfig.tenantId ?? 'common',
            scope: tokenData.scope,
            verifyEndpoint: `${baseUrl}/oauth/verify`,
            logger: {
              info: console.log,
              error: console.error,
              warn: console.warn,
              debug: () => {},
            },
          });

          // Refresh the Microsoft access token
          refreshedProviderTokens = await provider.refreshAccessToken(tokenData.providerTokens.refreshToken);
        } catch (error) {
          // If refresh fails, continue with existing tokens (they may still be valid)
          console.warn('Provider token refresh failed, using existing tokens:', error instanceof Error ? error.message : String(error));
        }
      }

      // Generate new DCR access token
      const newAccessToken = randomUUID();
      const newTokenData: AccessToken = {
        ...tokenData,
        access_token: newAccessToken,
        created_at: Date.now(),
      };

      await dcrUtils.setAccessToken(store, newAccessToken, newTokenData);

      // Store refreshed provider tokens indexed by new DCR access token
      await dcrUtils.setProviderTokens(store, newAccessToken, refreshedProviderTokens);

      return res.json({
        access_token: newTokenData.access_token,
        token_type: newTokenData.token_type,
        expires_in: newTokenData.expires_in,
        scope: newTokenData.scope,
      });
    }
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code and refresh_token grants are supported',
    });
  });

  /**
   * OAuth Token Revocation (RFC 7009)
   * POST /oauth/revoke
   */
  router.post('/oauth/revoke', async (req: Request, res: Response) => {
    const { token, token_type_hint, client_id, client_secret } = req.body;

    if (!token) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'token is required',
      });
    }

    // Validate client if credentials provided
    if (client_id && client_secret) {
      const isValidClient = await dcrUtils.validateClient(store, client_id, client_secret);
      if (!isValidClient) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials',
        });
      }
    }

    // Revoke the token
    if (token_type_hint === 'refresh_token') {
      await dcrUtils.deleteRefreshToken(store, token);
    } else if (token_type_hint === 'access_token') {
      await dcrUtils.deleteAccessToken(store, token);
      await dcrUtils.deleteProviderTokens(store, token);
    } else {
      // No hint - try both
      await dcrUtils.deleteRefreshToken(store, token);
      await dcrUtils.deleteAccessToken(store, token);
      await dcrUtils.deleteProviderTokens(store, token);
    }

    // RFC 7009: Return 200 even if token not found
    return res.status(200).send();
  });

  /**
   * Token Verification Endpoint
   * GET /oauth/verify
   *
   * Validates bearer tokens for Resource Server.
   * Returns AuthInfo with provider tokens for stateless DCR pattern.
   */
  router.get('/oauth/verify', async (req: Request, res: Response) => {
    // Extract bearer token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'invalid_request',
        error_description: 'Missing or invalid Authorization header',
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Validate token exists in access tokens store
    const tokenData = await dcrUtils.getAccessToken(store, token);

    if (!tokenData) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Unknown or expired access token',
      });
    }

    // Check if token is expired
    const now = Date.now();
    const expiresAt = tokenData.created_at + tokenData.expires_in * 1000;

    if (now > expiresAt) {
      // Remove expired token
      await dcrUtils.deleteAccessToken(store, token);
      await dcrUtils.deleteProviderTokens(store, token);
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token has expired',
      });
    }

    // Return AuthInfo with provider tokens for stateless DCR
    const authInfo = {
      token,
      clientId: tokenData.client_id,
      scopes: tokenData.scope ? tokenData.scope.split(' ') : [],
      expiresAt,
      providerTokens: tokenData.providerTokens,
    };

    return res.json(authInfo);
  });

  /**
   * Debug endpoint to list registered clients (development only)
   */
  router.get('/debug/clients', async (_req: Request, res: Response) => {
    const clients = await dcrUtils.listClients(store);
    res.json(clients);
  });

  return router;
}
