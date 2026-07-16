export interface AssertSafeUrlOptions {
  /**
   * DNS resolver, injectable for testing. Defaults to `dns.promises.lookup`.
   */
  lookup?: (
    hostname: string,
    options: { all: true }
  ) => Promise<Array<{ address: string; family: number }>>;
}

/**
 * Error thrown when a URL is rejected by {@link assertSafeUrl}.
 * `code` is always `'UNSAFE_URL'`.
 */
export class UnsafeUrlError extends Error {
  readonly name: 'UnsafeUrlError';
  readonly code: 'UNSAFE_URL';
}

/**
 * Returns true if `ip` is loopback, private, link-local, CGNAT, or otherwise
 * reserved (including 169.254.169.254). Fails closed on unparseable input.
 */
export function isPrivateOrReservedIp(ip: string): boolean;

/**
 * SSRF guard. Rejects non-http(s) URLs and any host that resolves to a
 * private/internal address; resolves to the parsed URL on success.
 */
export function assertSafeUrl(
  url: string,
  options?: AssertSafeUrlOptions
): Promise<URL>;

export default assertSafeUrl;
