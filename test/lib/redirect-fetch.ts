/**
 * Routes fetches for one provider host to a local server, leaving every other URL alone.
 *
 * The provider token URLs are hard-coded in this package, and adding a public option for a
 * test is not allowed, so this is the narrowest seam: the request, headers and body still go
 * over real HTTP to a controlled server that answers per RFC 6749. Returns a restore function.
 */
export function redirectFetch(host: string, localBase: string): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const target = new URL(url);
    if (target.host === host) return original(`${localBase}${target.pathname}${target.search}`, init);
    return original(input, init);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}
