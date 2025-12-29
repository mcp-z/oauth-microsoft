import { z } from 'zod';

export const AuthRequiredBranchSchema = z.object({
  type: z.literal('auth_required'),
  provider: z.string(),
  message: z.string(),
  url: z.string().optional(),
});
export type AuthRequiredBranch = z.infer<typeof AuthRequiredBranchSchema>;

export const AuthRequiredSchema = z
  .object({
    type: z.literal('auth_required'),
    provider: z.string().describe('OAuth provider name (e.g., "google")'),
    message: z.string().describe('Human-readable message explaining why auth is needed'),
    url: z.string().url().describe('Authentication URL to open in browser'),
    flow: z.string().optional().describe('Authentication flow type (e.g., "auth_url", "device_code")'),
    instructions: z.string().describe('Clear instructions for the user'),
    user_code: z.string().optional().describe('Code user must enter at verification URL (device flows only)'),
    expires_in: z.number().optional().describe('Seconds until code expires (device flows only)'),
    accountId: z.string().optional().describe('Account identifier (email) that requires authentication'),
  })
  .describe('Authentication required with clear actionable instructions for user');

export type AuthRequired = z.infer<typeof AuthRequiredSchema>;
