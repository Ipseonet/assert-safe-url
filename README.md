# @ipseonet/assert-safe-url

Zero-dependency **SSRF guard** for Node.js. Before your server fetches a
URL that a user supplied, run it through `assertSafeUrl` — it rejects anything
that isn't plain `http(s)` or that resolves to a **private, loopback,
link-local, CGNAT, or cloud-metadata** address (including the notorious
`169.254.169.254`).

- **No dependencies, no build step** — just Node's `dns` and `net`.
- **Fails closed** — unparseable IPs and DNS failures are treated as unsafe.
- **Checks every resolved address**, defending against DNS-rebinding tricks.
- **TypeScript types included.**

## Install

```sh
npm install @ipseonet/assert-safe-url
```

## Usage

```js
// CommonJS
const assertSafeUrl = require('@ipseonet/assert-safe-url')

// ESM
import assertSafeUrl from '@ipseonet/assert-safe-url'

app.post('/fetch', async (req, res) => {
  let url
  try {
    url = await assertSafeUrl(req.body.url) // resolves to a parsed URL
  } catch (err) {
    return res.status(400).json({ error: err.message }) // UnsafeUrlError
  }
  const upstream = await fetch(url)
  // ...
})
```

### Named exports

```js
const {
  assertSafeUrl,
  isPrivateOrReservedIp,
  UnsafeUrlError
} = require('@ipseonet/assert-safe-url')

isPrivateOrReservedIp('169.254.169.254') // → true
isPrivateOrReservedIp('8.8.8.8')         // → false
```

## API

### `assertSafeUrl(url[, options]) => Promise<URL>`

Resolves to the parsed [`URL`](https://developer.mozilla.org/docs/Web/API/URL)
when the target is safe. Throws `UnsafeUrlError` (with `code === 'UNSAFE_URL'`)
when the URL is malformed, uses a non-http(s) protocol, cannot be resolved, or
resolves to any private/internal address.

- `options.lookup` — inject a custom DNS resolver
  `(hostname, { all: true }) => Promise<Array<{ address, family }>>`.
  Defaults to `dns.promises.lookup`. Useful for testing.

### `isPrivateOrReservedIp(ip) => boolean`

Synchronous check for a single IP literal (IPv4, IPv6, or IPv4-mapped IPv6).
Returns `true` for reserved ranges and for anything it cannot parse.

### `class UnsafeUrlError extends Error`

`name === 'UnsafeUrlError'`, `code === 'UNSAFE_URL'`.

## What it blocks

| Range | Example |
| --- | --- |
| Loopback | `127.0.0.0/8`, `::1` |
| Private IPv4 | `10/8`, `172.16/12`, `192.168/16` |
| Link-local / metadata | `169.254.0.0/16` (incl. `169.254.169.254`), `fe80::/10` |
| CGNAT | `100.64.0.0/10` |
| Unique-local IPv6 | `fc00::/7` |
| Unspecified | `0.0.0.0/8` |
| Non-http(s) protocols | `file:`, `ftp:`, `gopher:`, … |

> **Scope:** this is a guard against server requests being aimed at internal
> infrastructure. It resolves DNS and checks the resulting addresses; it does
> not, by itself, prevent TOCTOU rebinding between the check and a later
> connection — pin or re-validate the resolved address at connect time for the
> strongest guarantee.

## License

[MIT](./LICENSE) © IPSEONET LLC
