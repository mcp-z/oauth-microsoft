import assert from 'assert';
import { createServer, type Server } from 'http';
import type { AddressInfo } from 'net';
import { fetchWithTimeout } from '../../../src/lib/fetch-with-timeout.ts';
import { DcrTokenVerifier } from '../../../src/lib/token-verifier.ts';
import { verifyTimeout } from '../../../src/lib/verify-timeout.ts';

// A server that sends headers and part of a body, then never finishes the response.
async function startStallingServer(): Promise<{ server: Server; url: string }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"partial":');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/` };
}

function stop(server: Server): Promise<void> {
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  return new Promise<void>((resolve) => server.close(() => resolve()));
}

describe('unit/fetch-with-timeout', () => {
  let server: Server;
  let url: string;

  before(async () => {
    ({ server, url } = await startStallingServer());
  });

  after(async () => {
    await stop(server);
  });

  it('rejects with the timeout message when the server sends headers and then stalls the body', async () => {
    await assert.rejects(async () => {
      const response = await fetchWithTimeout(url, undefined, 50);
      await response.text();
    }, /^Error: Request timeout after 50ms$/);
  });

  it('DcrTokenVerifier.verifyAccessToken rejects with the timeout message when the verify body stalls', async () => {
    const original = verifyTimeout.ms;
    verifyTimeout.ms = 50;
    try {
      await assert.rejects(new DcrTokenVerifier(url).verifyAccessToken('any-token'), /^Error: Request timeout after 50ms$/);
    } finally {
      verifyTimeout.ms = original;
    }
  });
});
