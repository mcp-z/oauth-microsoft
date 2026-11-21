import type { Express } from 'express';
import type { Server } from 'http';
import type { AddressInfo } from 'net';

/** Binds the app to an OS-assigned port on the named host and returns once the server is listening, so the port is never guessed ahead of the bind. */
export async function listenOnFreePort(app: Express, host: string): Promise<{ server: Server; port: number }> {
  const server = app.listen(0, host);
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  return { server, port: (server.address() as AddressInfo).port };
}
