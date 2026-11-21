/**
 * Loopback OAuth callback router
 *
 * Handles GET /oauth/callback for persistent redirectUri deployments.
 */

import { getErrorTemplate, getSuccessTemplate } from '@mcp-z/oauth';
import type { Request, Response } from 'express';
import express from 'express';
import type { LoopbackOAuthProvider } from '../providers/loopback-oauth.ts';

export function createLoopbackCallbackRouter(provider: LoopbackOAuthProvider): express.Router {
  const router = express.Router();

  router.get('/oauth/callback', async (req: Request, res: Response) => {
    const code = typeof req.query.code === 'string' ? req.query.code : undefined;
    const state = typeof req.query.state === 'string' ? req.query.state : undefined;
    const error = typeof req.query.error === 'string' ? req.query.error : undefined;
    const errorDescription = typeof req.query.error_description === 'string' ? req.query.error_description : undefined;

    if (error) {
      provider.failOAuthCallback({ state, error, errorDescription });
      res.status(400).send(getErrorTemplate(error));
      return;
    }

    if (!code) {
      provider.failOAuthCallback({ state });
      res.status(400).send(getErrorTemplate('No authorization code received'));
      return;
    }

    try {
      await provider.handleOAuthCallback({ code, state });
      res.status(200).send(getSuccessTemplate());
    } catch (callbackError) {
      res.status(500).send(getErrorTemplate(callbackError instanceof Error ? callbackError.message : 'Token exchange failed'));
    }
  });

  return router;
}
