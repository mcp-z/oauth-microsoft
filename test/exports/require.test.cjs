const assert = require('assert');
const { createConfig, createDcrRouter, createLoopbackCallbackRouter, parseConfig, parseDcrConfig, verifyBearerToken } = require('@mcp-z/oauth-microsoft');

describe('exports .cjs', () => {
  it('named exports resolve', () => {
    for (const fn of [createDcrRouter, verifyBearerToken, createLoopbackCallbackRouter, createConfig, parseConfig, parseDcrConfig]) assert.equal(typeof fn, 'function');
  });
});
