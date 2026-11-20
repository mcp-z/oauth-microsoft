/**
 * Fetch with one time bound that covers the request and reading the response body,
 * so a server that sends headers and then stalls cannot hold a call open.
 *
 * The body is read inside the bound and returned as a buffered `Response`.
 *
 * @param url - URL to fetch
 * @param options - Fetch options
 * @param timeoutMs - Timeout in milliseconds (default: 30000)
 * @returns Fetch response with its body already read
 * @throws Error if the request or the body read times out
 */
export async function fetchWithTimeout(url: string, options?: RequestInit, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    const body = await response.arrayBuffer();
    // Statuses without a body (204, 205, 304) reject a non-null body.
    return new Response(body.byteLength > 0 ? body : null, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`Request timeout after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
