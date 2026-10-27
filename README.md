# http-basic-authentication-challenge-decode

Decodes an HTTP Basic `Authorization` header into its `{ username, password }` credential pair. Returns `null` when the header is missing, uses a non-Basic scheme, or cannot be base64-decoded.

## Usage

```js
import { decodeBasicAuth } from 'http-basic-authentication-challenge-decode';

const creds = decodeBasicAuth('Basic YWxpY2U6c2VjcmV0');
// { username: 'alice', password: 'secret' }
```

## Why this exists

Parsing the Basic auth header looks like a one-liner but has a couple of sharp edges: the scheme token is case-insensitive (`basic`, `BASIC`, `BaSiC` are all legal), and the password may contain a colon — so you must split on the *first* colon, not all of them. This library does both correctly and returns a consistent `null` for anything it cannot decode, so callers can branch on truthiness instead of catching `URIError` from `atob` or `SyntaxError` from bad input.

The `decodeBasicCredentials` export takes just the base64 segment (everything after `Basic `) for cases where the caller has already stripped the prefix.

## Edge cases

- An empty username (`:secret`) or empty password (`alice:`) is valid and decodes to an empty string for the missing half.
- Credentials are decoded as UTF-8 per RFC 7617, not ISO-8859-1. This matches what every modern browser sends and what servers expect.
- A header with no colon after decoding (e.g. a bare username) returns `null`.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

