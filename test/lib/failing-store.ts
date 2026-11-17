import Keyv from 'keyv';

/** A real Keyv over an in-memory adapter whose writes (set, delete) fail once `fail()` is called. Reads keep working. */
export function createFailingStore(): { store: Keyv<unknown>; fail: () => void } {
  const data = new Map<string, unknown>();
  let failing = false;
  const adapter = {
    get: async (key: string) => data.get(key),
    set: async (key: string, value: unknown) => {
      if (failing) throw new Error('store write failed');
      data.set(key, value);
      return true;
    },
    delete: async (key: string) => {
      if (failing) throw new Error('store write failed');
      return data.delete(key);
    },
    clear: async () => data.clear(),
  };
  return {
    store: new Keyv<unknown>(adapter as never),
    fail: () => {
      failing = true;
    },
  };
}
