import type { CiConfig } from './lib/ci-setup.ts';

export const config = {
  provider: 'microsoft',
  flows: [
    {
      id: 'loopback-microsoft',
      refreshTokenSecret: 'TEST_REFRESH_TOKEN',
      scopeSecret: 'TEST_SCOPE',
      clientIdSecret: 'MS_CLIENT_ID',
      clientSecretSecret: 'MS_CLIENT_SECRET',
      clientSecretRequired: false,
      tenantSecret: 'MS_TENANT_ID',
      storage: {
        kind: 'account',
        path: '.tokens/test/store.json',
        service: 'outlook',
        accountId: {
          env: 'TEST_ACCOUNT_ID',
        },
      },
    },
    {
      id: 'device-microsoft',
      refreshTokenSecret: 'TEST_DEVICE_REFRESH_TOKEN',
      scopeSecret: 'TEST_DEVICE_SCOPE',
      clientIdSecret: 'MS_CLIENT_ID',
      clientSecretSecret: 'MS_CLIENT_SECRET',
      clientSecretRequired: false,
      tenantSecret: 'MS_TENANT_ID',
      storage: {
        kind: 'account',
        path: '.tokens/test/store.json',
        service: 'outlook',
        accountId: {
          value: 'device-code',
        },
      },
    },
    {
      id: 'dcr-microsoft',
      refreshTokenSecret: 'TEST_DCR_REFRESH_TOKEN',
      scopeSecret: 'TEST_DCR_SCOPE',
      clientIdSecret: 'MS_TEST_DCR_CLIENT_ID',
      clientSecretSecret: 'MS_TEST_DCR_CLIENT_SECRET',
      clientSecretRequired: false,
      tenantSecret: 'MS_TEST_DCR_TENANT_ID',
      storage: {
        kind: 'dcr',
        path: '.tokens/dcr.json',
        key: 'microsoft',
        registration: {
          clientIdSecret: 'TEST_DCR_CLIENT_ID',
          clientSecretSecret: 'TEST_DCR_CLIENT_SECRET',
        },
      },
    },
  ],
  requiredTestSecrets: [],
  serviceAccount: null,
} as const satisfies CiConfig;
