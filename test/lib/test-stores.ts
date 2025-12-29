/**
 * In-memory stores for testing
 *
 * Provides lightweight Keyv storage implementations for unit tests.
 * Avoids file system I/O and allows clean state between tests.
 */

/**
 * In-memory Keyv storage implementation
 *
 * @example
 * ```typescript
 * const tokenStore = new InMemoryStore();
 * await tokenStore.set('alice:outlook:token', { access_token: '...' });
 * const token = await tokenStore.get('alice:outlook:token');
 * ```
 */
export class InMemoryStore<T = unknown> {
  private store = new Map<string, T>();

  async get(key: string): Promise<T | undefined> {
    return this.store.get(key);
  }

  async set(key: string, value: T): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async clear(): Promise<void> {
    this.store.clear();
  }

  /**
   * Multi-get operation for batch retrieval
   */
  async multiGet(keys: string[]): Promise<Array<[string, T | undefined]>> {
    return keys.map((key) => [key, this.store.get(key)]);
  }

  /**
   * Multi-set operation for batch updates
   */
  async multiSet(entries: Array<[string, T]>): Promise<void> {
    for (const [key, value] of entries) {
      this.store.set(key, value);
    }
  }

  /**
   * Multi-remove operation for batch deletion
   */
  async multiRemove(keys: string[]): Promise<void> {
    for (const key of keys) {
      this.store.delete(key);
    }
  }

  /**
   * Get all keys in store (for testing/debugging)
   */
  getAllKeys(): string[] {
    return Array.from(this.store.keys());
  }

  /**
   * Get size of store (for testing/debugging)
   */
  size(): number {
    return this.store.size;
  }
}
