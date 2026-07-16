'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const assertSafeUrl = require('..')
const { isPrivateOrReservedIp, UnsafeUrlError } = require('..')

// Fake DNS resolver so tests never touch the network.
const lookupReturning = (...addrs) => async () =>
  addrs.map((address) => ({ address, family: net_family(address) }))
function net_family(a) {
  return a.includes(':') ? 6 : 4
}

test('isPrivateOrReservedIp: IPv4 private/reserved ranges are blocked', () => {
  for (const ip of [
    '127.0.0.1', '10.0.0.1', '172.16.5.4', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1'
  ]) {
    assert.equal(isPrivateOrReservedIp(ip), true, `${ip} should be blocked`)
  }
})

test('isPrivateOrReservedIp: public IPv4 is allowed', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1']) {
    assert.equal(isPrivateOrReservedIp(ip), false, `${ip} should be allowed`)
  }
})

test('isPrivateOrReservedIp: IPv6 loopback/link-local/ULA blocked, public allowed', () => {
  assert.equal(isPrivateOrReservedIp('::1'), true)
  assert.equal(isPrivateOrReservedIp('fe80::1'), true)
  assert.equal(isPrivateOrReservedIp('fc00::1'), true)
  assert.equal(isPrivateOrReservedIp('fd12:3456::1'), true)
  assert.equal(isPrivateOrReservedIp('2606:4700:4700::1111'), false)
})

test('isPrivateOrReservedIp: IPv4-mapped IPv6 unwraps and re-checks', () => {
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true)
  assert.equal(isPrivateOrReservedIp('::ffff:8.8.8.8'), false)
})

test('isPrivateOrReservedIp: unparseable input fails closed', () => {
  assert.equal(isPrivateOrReservedIp('not-an-ip'), true)
  assert.equal(isPrivateOrReservedIp(''), true)
})

test('assertSafeUrl: rejects non-http(s) protocols', async () => {
  for (const url of ['file:///etc/passwd', 'ftp://example.com', 'gopher://x']) {
    await assert.rejects(() => assertSafeUrl(url, { lookup: lookupReturning('8.8.8.8') }), UnsafeUrlError)
  }
})

test('assertSafeUrl: rejects malformed URLs', async () => {
  await assert.rejects(() => assertSafeUrl('http://', { lookup: lookupReturning('8.8.8.8') }), UnsafeUrlError)
  await assert.rejects(() => assertSafeUrl('not a url', { lookup: lookupReturning('8.8.8.8') }), UnsafeUrlError)
})

test('assertSafeUrl: rejects hosts resolving to a private address', async () => {
  await assert.rejects(
    () => assertSafeUrl('http://internal.example', { lookup: lookupReturning('127.0.0.1') }),
    (err) => err instanceof UnsafeUrlError && err.code === 'UNSAFE_URL'
  )
})

test('assertSafeUrl: rejects the cloud-metadata endpoint', async () => {
  await assert.rejects(
    () => assertSafeUrl('http://metadata.example', { lookup: lookupReturning('169.254.169.254') }),
    UnsafeUrlError
  )
})

test('assertSafeUrl: rejects when ANY resolved address is private (rebinding defense)', async () => {
  await assert.rejects(
    () => assertSafeUrl('http://mixed.example', { lookup: lookupReturning('8.8.8.8', '10.0.0.5') }),
    UnsafeUrlError
  )
})

test('assertSafeUrl: resolves to the parsed URL for a public host', async () => {
  const out = await assertSafeUrl('https://example.com/path?q=1', { lookup: lookupReturning('93.184.216.34') })
  assert.ok(out instanceof URL)
  assert.equal(out.hostname, 'example.com')
  assert.equal(out.pathname, '/path')
})

test('assertSafeUrl: surfaces DNS failure as UnsafeUrlError', async () => {
  const failing = async () => { throw new Error('ENOTFOUND') }
  await assert.rejects(() => assertSafeUrl('http://nope.example', { lookup: failing }), UnsafeUrlError)
})
