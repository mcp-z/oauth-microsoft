import type { EnrichedExtra } from '../../src/index.ts';
import type { UserAuthProvider } from '../../src/types.ts';

/**
 * Create test extra object for handler tests
 */
export function createTestExtra(overrides?: Partial<Omit<EnrichedExtra, 'mcpReq'>> & { mcpReq?: Partial<EnrichedExtra['mcpReq']> }): EnrichedExtra {
  const { mcpReq, ...rest } = overrides ?? {};
  return {
    http: { req: new Request('http://test.local', { method: 'POST' }) },
    ...rest,
    mcpReq: { _meta: {}, ...mcpReq },
  } as EnrichedExtra;
}

/**
 * Silent logger for tests
 */
export const logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/** Test provider that reads accountId from request object for testing */
export class TestUserAuthProvider implements UserAuthProvider {
  /**
   * Extract account ID from request
   * For tests, we set the accountId directly on the request object
   */
  async getUserId(req: unknown): Promise<string> {
    if (!req || !(req as { accountId?: string }).accountId) {
      throw new Error('Authentication failed: missing accountId in request');
    }
    return (req as { accountId: string }).accountId;
  }

  /**
   * Set account ID for a request (test helper)
   */
  setUserId(req: unknown, accountId: string): void {
    (req as { accountId: string }).accountId = accountId;
  }
}
