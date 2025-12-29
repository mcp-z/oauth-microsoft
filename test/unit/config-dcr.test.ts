import '../lib/env-loader.js';

import assert from 'assert';
import { type DcrConfig, parseDcrConfig } from '../../src/setup/config.ts';

describe('parseDcrConfig', () => {
  const testScope = 'https://graph.microsoft.com/.default';

  describe('Valid configurations', () => {
    it('parses valid self-hosted mode with all environment variables', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'self-hosted');
      assert.strictEqual(config.storeUri, 'file://.dcr.json');
      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
      assert.strictEqual(config.tenantId, 'common');
      assert.strictEqual(config.scope, testScope);
      assert.strictEqual(config.verifyUrl, undefined);
    });

    it('parses valid external mode with verifyUrl', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: 'organizations',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(config.verifyUrl, 'https://auth.example.com/oauth/verify');
      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
      assert.strictEqual(config.tenantId, 'organizations');
      assert.strictEqual(config.scope, testScope);
      assert.strictEqual(config.storeUri, undefined);
    });

    it('parses config with optional client secret omitted', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, undefined);
    });
  });

  describe('Default values', () => {
    it('defaults to self-hosted mode when DCR_MODE not specified', () => {
      const env = {
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'self-hosted');
      assert.strictEqual(config.storeUri, 'file://.dcr.json');
    });
  });

  describe('CLI arguments override environment variables', () => {
    it('CLI --dcr-mode overrides DCR_MODE env var', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig(['--dcr-mode=external'], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(config.verifyUrl, 'https://auth.example.com/oauth/verify');
    });

    it('CLI --dcr-verify-url overrides DCR_VERIFY_URL env var', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://old.example.com/verify',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig(['--dcr-verify-url=https://new.example.com/verify'], env, testScope);

      assert.strictEqual(config.verifyUrl, 'https://new.example.com/verify');
    });

    it('CLI --dcr-store-uri overrides DCR_STORE_URI env var', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://old-path/store.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config = parseDcrConfig(['--dcr-store-uri=file://new-path/store.json'], env, testScope);

      assert.strictEqual(config.storeUri, 'file://new-path/store.json');
    });
  });

  describe('Invalid mode value', () => {
    it('throws error for invalid --dcr-mode value', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseDcrConfig(['--dcr-mode=invalid'], env, testScope), {
        name: 'Error',
        message: 'Invalid --dcr-mode value: "invalid". Valid values: self-hosted, external',
      });
    });

    it('throws error for invalid DCR_MODE env var', () => {
      const env = {
        DCR_MODE: 'invalid',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Invalid --dcr-mode value: "invalid". Valid values: self-hosted, external',
      });
    });
  });

  describe('Mode-specific required field validation', () => {
    it('throws error when verifyUrl missing in external mode', () => {
      const env = {
        DCR_MODE: 'external',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'DCR external mode requires --dcr-verify-url or DCR_VERIFY_URL environment variable',
      });
    });

    it('throws error when MS_CLIENT_ID is missing', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable MS_CLIENT_ID is required for DCR configuration',
      });
    });

    it('throws error when MS_CLIENT_ID is empty string', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: '',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable MS_CLIENT_ID is required for DCR configuration',
      });
    });

    it('throws error when MS_TENANT_ID is missing', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable MS_TENANT_ID is required for DCR configuration',
      });
    });

    it('throws error when MS_TENANT_ID is empty string', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: '',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable MS_TENANT_ID is required for DCR configuration',
      });
    });
  });

  describe('Type structure', () => {
    it('returns correct type structure for self-hosted mode', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-secret',
        MS_TENANT_ID: 'common',
      };

      const config: DcrConfig = parseDcrConfig([], env, testScope);

      // Type assertions - should compile without errors
      assert.ok(config.mode === 'self-hosted' || config.mode === 'external');
      assert.ok(typeof config.verifyUrl === 'string' || config.verifyUrl === undefined);
      assert.ok(typeof config.storeUri === 'string' || config.storeUri === undefined);
      assert.ok(typeof config.clientId === 'string');
      assert.ok(typeof config.clientSecret === 'string' || config.clientSecret === undefined);
      assert.ok(typeof config.tenantId === 'string');
      assert.ok(typeof config.scope === 'string');
    });

    it('returns correct type structure for external mode', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'common',
      };

      const config: DcrConfig = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(typeof config.verifyUrl, 'string');
      assert.strictEqual(config.storeUri, undefined);
    });
  });
});
