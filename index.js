'use strict'

const dns = require('dns').promises
const net = require('net')

/**
 * Error thrown when a URL is rejected by {@link assertSafeUrl}.
 * `code` is always `'UNSAFE_URL'` so callers can branch without string-matching.
 */
class UnsafeUrlError extends Error {
  constructor(message) {
    super(message)
    this.name = 'UnsafeUrlError'
    this.code = 'UNSAFE_URL'
  }
}

/**
 * Returns true if `ip` is a loopback, private, link-local, CGNAT, or otherwise
 * reserved address — including the 169.254.169.254 cloud-metadata endpoint.
 * Fails closed: anything it cannot parse is treated as unsafe.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateOrReservedIp(ip) {
  const version = net.isIP(ip)
  if (version === 4) {
    const [a, b] = ip.split('.').map(Number)
    if (a === 127) return true // loopback 127.0.0.0/8
    if (a === 10) return true // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
    if (a === 192 && b === 168) return true // 192.168.0.0/16
    if (a === 169 && b === 254) return true // 169.254.0.0/16 (incl. cloud metadata)
    if (a === 0) return true // 0.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10 (CGNAT)
    return false
  }
  if (version === 6) {
    const lower = ip.toLowerCase()
    if (lower === '::1') return true // loopback
    if (lower.startsWith('fe80:')) return true // link-local fe80::/10
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true // unique local fc00::/7
    if (lower.startsWith('::ffff:')) {
      // IPv4-mapped IPv6 — unwrap and re-check the embedded v4 address.
      const v4 = lower.replace('::ffff:', '')
      if (net.isIP(v4) === 4) return isPrivateOrReservedIp(v4)
    }
    return false
  }
  return true // not a parseable IP — fail closed
}

/**
 * @typedef {Object} AssertSafeUrlOptions
 * @property {(hostname: string, options: { all: true }) =>
 *   Promise<Array<{ address: string, family: number }>>} [lookup]
 *   DNS resolver, injectable for testing. Defaults to `dns.promises.lookup`.
 */

/**
 * SSRF guard for any server-side fetch of a caller-supplied URL.
 *
 * Rejects the URL (throwing {@link UnsafeUrlError}) when it is not plain
 * http(s), cannot be parsed, cannot be resolved, or resolves to ANY
 * private/loopback/link-local/CGNAT/metadata address. Resolves to the parsed
 * `URL` on success.
 *
 * @param {string} url
 * @param {AssertSafeUrlOptions} [options]
 * @returns {Promise<URL>}
 */
async function assertSafeUrl(url, options = {}) {
  const lookup = options.lookup || dns.lookup

  let parsed
  try {
    parsed = new URL(url)
  } catch (e) {
    throw new UnsafeUrlError('Not a valid URL.')
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UnsafeUrlError(`Blocked: unsupported protocol "${parsed.protocol}"`)
  }

  let addresses
  try {
    addresses = await lookup(parsed.hostname, { all: true })
  } catch (err) {
    throw new UnsafeUrlError(`Could not resolve host "${parsed.hostname}"`)
  }

  for (const { address } of addresses) {
    if (isPrivateOrReservedIp(address)) {
      throw new UnsafeUrlError(`Blocked: "${parsed.hostname}" resolves to a private/internal address`)
    }
  }

  return parsed
}

module.exports = assertSafeUrl
module.exports.assertSafeUrl = assertSafeUrl
module.exports.isPrivateOrReservedIp = isPrivateOrReservedIp
module.exports.UnsafeUrlError = UnsafeUrlError
