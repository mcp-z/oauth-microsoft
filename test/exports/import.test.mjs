import { createConfig, createDcrRouter, createLoopbackCallbackRouter, parseConfig, parseDcrConfig, verifyBearerToken } from '@mcp-z/oauth-microsoft';
import assert from 'assert';

describe('exports .mjs', () => {
  it('named exports resolve', () => {
    for (const fn of [createDcrRouter, verifyBearerToken, createLoopbackCallbackRouter, createConfig, parseConfig, parseDcrConfig]) assert.equal(typeof fn, 'function');
  });
});
