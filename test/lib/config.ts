/**
 * Microsoft OAuth test configuration imports from source config.
 * Re-exports OAuth parsing functions for consistent test patterns.
 *
 * This ensures tests use the same config parsing as production code.
 */

export { createConfig, type OAuthConfig, parseConfig } from '../../src/setup/config.ts';
