import '../lib/env-loader.ts';

import assert from 'assert';
import { type OAuthConfig, parseConfig } from '../../src/setup/config.ts';

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
