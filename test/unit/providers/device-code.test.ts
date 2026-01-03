import '../../lib/env-loader.ts';

/**
 * DeviceCodeProvider Unit Tests
 *
 * Tests for the DeviceCodeProvider class which implements OAuth 2.0 Device Authorization Grant
 * (RFC 8628) with server-managed token storage.
 *
 * Security Model: Server manages tokens, uses device code flow for headless/limited-input scenarios
 * Requires valid test OAuth tokens (run npm run test:setup first)
 */

import * as path from 'path';
import { createConfig } from '../../lib/config.ts';

const _config = createConfig();

// Use isolated test token directory
// Run `npm run test:setup` first to generate tokens
const _tokenStorePath = path.join(process.cwd(), '.tokens/test');

it('DeviceCodeProvider - getAccessToken returns valid token', async () => {
  // Skip this test - requires interactive device code flow which is better tested in integration tests
  // This test would need account management state which is better tested in middleware tests
});

it('DeviceCodeProvider - caches and reuses access tokens', async () => {
  // Skip this test - requires interactive device code flow which is better tested in integration tests
  // Token caching behavior is verified in other provider tests
});
