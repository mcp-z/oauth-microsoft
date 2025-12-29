/**
 * DCR Client Utils Unit Tests
 */

import assert from 'assert';
import Keyv from 'keyv';
import * as dcrUtils from '../../../src/lib/dcr-utils.ts';
import type { DcrClientMetadata } from '../../../src/types.ts';

describe('DCR Client Utils', () => {
  let store: Keyv;

  beforeEach(() => {
    // Use in-memory store for testing
    store = new Keyv();
  });

  afterEach(async () => {
    await store.clear();
  });

  it('registers a client with minimal metadata', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback'],
    };

    const client = await dcrUtils.registerClient(store, metadata);

    assert.ok(client.client_id);
    assert.ok(client.client_secret);
    assert.ok(client.client_id.startsWith('dcr_'));
    assert.strictEqual(client.client_secret_expires_at, 0);
    assert.deepStrictEqual(client.redirect_uris, metadata.redirect_uris);
    assert.deepStrictEqual(client.grant_types, ['authorization_code', 'refresh_token']);
    assert.deepStrictEqual(client.response_types, ['code']);
  });

  it('registers a client with full metadata', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback'],
      client_name: 'Test Client',
      client_uri: 'http://localhost:3000',
      logo_uri: 'http://localhost:3000/logo.png',
      scope: 'Mail.Read Mail.Send',
      contacts: ['admin@example.com'],
      tos_uri: 'http://localhost:3000/tos',
      policy_uri: 'http://localhost:3000/privacy',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
    };

    const client = await dcrUtils.registerClient(store, metadata);

    assert.ok(client.client_id);
    assert.strictEqual(client.client_name, metadata.client_name);
    assert.strictEqual(client.client_uri, metadata.client_uri);
    assert.strictEqual(client.logo_uri, metadata.logo_uri);
    assert.strictEqual(client.scope, metadata.scope);
    assert.deepStrictEqual(client.contacts, metadata.contacts);
    assert.strictEqual(client.tos_uri, metadata.tos_uri);
    assert.strictEqual(client.policy_uri, metadata.policy_uri);
    assert.deepStrictEqual(client.grant_types, metadata.grant_types);
    assert.deepStrictEqual(client.response_types, metadata.response_types);
    assert.strictEqual(client.token_endpoint_auth_method, metadata.token_endpoint_auth_method);
  });

  it('throws error when redirect_uris is missing', async () => {
    const metadata: DcrClientMetadata = {};

    await assert.rejects(async () => {
      await dcrUtils.registerClient(store, metadata);
    }, /redirect_uris is required/);
  });

  it('retrieves a registered client', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback'],
      client_name: 'Retrieval Test',
    };

    const registered = await dcrUtils.registerClient(store, metadata);
    const retrieved = await dcrUtils.getClient(store, registered.client_id);

    assert.ok(retrieved);
    assert.strictEqual(retrieved.client_id, registered.client_id);
    assert.strictEqual(retrieved.client_secret, registered.client_secret);
    assert.strictEqual(retrieved.client_name, metadata.client_name);
  });

  it('returns undefined for non-existent client', async () => {
    const client = await dcrUtils.getClient(store, 'non_existent_client');
    assert.strictEqual(client, undefined);
  });

  it('validates client credentials', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback'],
    };

    const client = await dcrUtils.registerClient(store, metadata);

    // Valid credentials
    const valid = await dcrUtils.validateClient(store, client.client_id, client.client_secret ?? '');
    assert.strictEqual(valid, true);

    // Invalid secret
    const invalidSecret = await dcrUtils.validateClient(store, client.client_id, 'wrong_secret');
    assert.strictEqual(invalidSecret, false);

    // Invalid client ID
    const invalidClient = await dcrUtils.validateClient(store, 'invalid_client', client.client_secret ?? '');
    assert.strictEqual(invalidClient, false);
  });

  it('validates redirect URIs', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback', 'http://localhost:3000/oauth/callback'],
    };

    const client = await dcrUtils.registerClient(store, metadata);

    // Valid URIs
    const valid1 = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://localhost:3000/callback');
    assert.strictEqual(valid1, true);

    const valid2 = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://localhost:3000/oauth/callback');
    assert.strictEqual(valid2, true);

    // Invalid URI
    const invalid = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://evil.com/callback');
    assert.strictEqual(invalid, false);

    // Invalid client ID
    const invalidClient = await dcrUtils.validateRedirectUri(store, 'invalid_client', 'http://localhost:3000/callback');
    assert.strictEqual(invalidClient, false);
  });

  it('lists all registered clients', async () => {
    const metadata1: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3001/callback'],
      client_name: 'Client 1',
    };

    const metadata2: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3002/callback'],
      client_name: 'Client 2',
    };

    await dcrUtils.registerClient(store, metadata1);
    await dcrUtils.registerClient(store, metadata2);

    const clients = await dcrUtils.listClients(store);

    assert.ok(clients.length >= 2);
    assert.ok(clients.some((c) => c.client_name === 'Client 1'));
    assert.ok(clients.some((c) => c.client_name === 'Client 2'));
  });

  it('deletes a client', async () => {
    const metadata: DcrClientMetadata = {
      redirect_uris: ['http://localhost:3000/callback'],
      client_name: 'Delete Test',
    };

    const client = await dcrUtils.registerClient(store, metadata);
    const beforeDelete = await dcrUtils.getClient(store, client.client_id);
    assert.ok(beforeDelete);

    await dcrUtils.deleteClient(store, client.client_id);
    const afterDelete = await dcrUtils.getClient(store, client.client_id);
    assert.strictEqual(afterDelete, undefined);
  });
});
