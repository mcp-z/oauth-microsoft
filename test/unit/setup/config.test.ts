import '../../lib/env-loader.ts';

import { type DcrConfig, type OAuthConfig, parseConfig, parseDcrConfig } from '@mcp-z/oauth-microsoft';
import assert from 'assert';

describe('parseConfig', () => {
  describe('Environment variables', () => {
    it('parses config with all environment variables', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: 'common',
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
      assert.strictEqual(config.tenantId, 'common');
    });

    it('parses config with optional client secret omitted', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_TENANT_ID: 'organizations',
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, undefined);
      assert.strictEqual(config.tenantId, 'organizations');
    });

    it('throws error when MS_CLIENT_ID is missing', () => {
      const env = {
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable MS_CLIENT_ID is required for Microsoft OAuth',
      });
    });

    it('throws error when MS_TENANT_ID is missing', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-client-secret',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable MS_TENANT_ID is required for Microsoft OAuth',
      });
    });

    it('throws error when MS_CLIENT_ID is empty string', () => {
      const env = {
        MS_CLIENT_ID: '',
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: 'common',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable MS_CLIENT_ID is required for Microsoft OAuth',
      });
    });

    it('throws error when MS_TENANT_ID is empty string', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-client-secret',
        MS_TENANT_ID: '',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable MS_TENANT_ID is required for Microsoft OAuth',
      });
    });

    it('handles undefined environment variables correctly', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: undefined,
        MS_TENANT_ID: 'consumers',
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id');
      assert.strictEqual(config.clientSecret, undefined);
      assert.strictEqual(config.tenantId, 'consumers');
    });

    it('supports all tenant ID variations', () => {
      const tenantIds = ['common', 'organizations', 'consumers', 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'];

      for (const tenantId of tenantIds) {
        const env = {
          MS_CLIENT_ID: 'test-client-id',
          MS_TENANT_ID: tenantId,
        };

        const config = parseConfig([], env);
        assert.strictEqual(config.tenantId, tenantId);
      }
    });
  });

  describe('Default values', () => {
    it('defaults to loopback-oauth auth mode', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig([], env);

      assert.strictEqual(config.auth, 'loopback-oauth');
    });

    it('defaults to single-user context (loopback OAuth only supports single-user)', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const _config = parseConfig([], env);
    });

    it('defaults headless to false when not specified', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig([], env);

      assert.strictEqual(config.headless, false);
    });
  });

  describe('CLI arguments', () => {
    it('parses --headless flag', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--headless'], env);

      assert.strictEqual(config.headless, true);
    });

    it('parses --redirect-uri', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--redirect-uri=https://api.example.com/callback'], env);

      assert.strictEqual(config.redirectUri, 'https://api.example.com/callback');
    });

    it('parses --tenant-id', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--tenant-id=organizations'], env);

      assert.strictEqual(config.tenantId, 'organizations');
    });

    it('CLI --headless overrides env HEADLESS', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', HEADLESS: 'false' };
      const config = parseConfig(['--headless'], env);

      assert.strictEqual(config.headless, true);
    });

    it('CLI --tenant-id overrides env MS_TENANT_ID', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--tenant-id=organizations'], env);

      assert.strictEqual(config.tenantId, 'organizations');
    });

    it('CLI --redirect-uri overrides env REDIRECT_URI', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', REDIRECT_URI: 'http://localhost:3000/old' };
      const config = parseConfig(['--redirect-uri=http://localhost:8080/oauth/callback'], env);

      assert.strictEqual(config.redirectUri, 'http://localhost:8080/oauth/callback');
    });
  });

  describe('Environment variable fallbacks', () => {
    it('uses HEADLESS env var', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', HEADLESS: 'true' };
      const config = parseConfig([], env);

      assert.strictEqual(config.headless, true);
    });

    it('uses REDIRECT_URI env var', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', REDIRECT_URI: 'http://localhost:8080/oauth/callback' };
      const config = parseConfig([], env);

      assert.strictEqual(config.redirectUri, 'http://localhost:8080/oauth/callback');
    });
  });

  describe('--auth argument', () => {
    describe('Valid modes', () => {
      it('parses --auth=loopback-oauth', () => {
        const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
        const config = parseConfig(['--auth=loopback-oauth'], env);

        assert.strictEqual(config.auth, 'loopback-oauth');
      });

      it('parses --auth=device-code', () => {
        const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
        const config = parseConfig(['--auth=device-code'], env);

        assert.strictEqual(config.auth, 'device-code');
      });
    });

    describe('Invalid modes', () => {
      it('throws error for invalid auth mode', () => {
        const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };

        assert.throws(() => parseConfig(['--auth=invalid'], env), {
          message: /Invalid --auth value: "invalid"/,
        });
      });
    });

    describe('AUTH_MODE environment variable', () => {
      it('uses AUTH_MODE env var', () => {
        const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', AUTH_MODE: 'loopback-oauth' };
        const config = parseConfig([], env);

        assert.strictEqual(config.auth, 'loopback-oauth');
      });

      it('CLI --auth overrides AUTH_MODE env var', () => {
        const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', AUTH_MODE: 'loopback-oauth' };
        const config = parseConfig(['--auth=device-code'], env);

        assert.strictEqual(config.auth, 'device-code');
      });
    });
  });

  describe('Type structure', () => {
    it('returns correct type structure', () => {
      const env = {
        MS_CLIENT_ID: 'test-client-id',
        MS_CLIENT_SECRET: 'test-secret',
        MS_TENANT_ID: 'common',
      };

      const config: OAuthConfig = parseConfig([], env);

      // Type assertions - should compile without errors
      assert.ok(typeof config.clientId === 'string');
      assert.ok(typeof config.clientSecret === 'string' || config.clientSecret === undefined);
      assert.ok(typeof config.tenantId === 'string');
      assert.ok(config.auth === 'loopback-oauth' || config.auth === 'device-code' || config.auth === 'dcr');
      assert.ok(typeof config.headless === 'boolean');
      assert.ok(typeof config.redirectUri === 'string' || config.redirectUri === undefined);
    });
  });

  describe('Transport validation', () => {
    it('allows DCR mode with HTTP transport', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--auth=dcr'], env, 'http');

      assert.strictEqual(config.auth, 'dcr');
    });

    it('allows DCR mode when transport not specified', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--auth=dcr'], env);

      assert.strictEqual(config.auth, 'dcr');
    });

    it('throws error for DCR mode with stdio transport', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };

      assert.throws(() => parseConfig(['--auth=dcr'], env, 'stdio'), {
        name: 'Error',
        message: 'DCR authentication mode requires HTTP transport. DCR is not supported with stdio transport.',
      });
    });

    it('throws error for DCR mode via AUTH_MODE env var with stdio transport', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common', AUTH_MODE: 'dcr' };

      assert.throws(() => parseConfig([], env, 'stdio'), {
        name: 'Error',
        message: 'DCR authentication mode requires HTTP transport. DCR is not supported with stdio transport.',
      });
    });

    it('allows loopback-oauth mode with stdio transport', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--auth=loopback-oauth'], env, 'stdio');

      assert.strictEqual(config.auth, 'loopback-oauth');
    });

    it('allows device-code mode with stdio transport', () => {
      const env = { MS_CLIENT_ID: 'test-id', MS_TENANT_ID: 'common' };
      const config = parseConfig(['--auth=device-code'], env, 'stdio');

      assert.strictEqual(config.auth, 'device-code');
    });
  });
});

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
