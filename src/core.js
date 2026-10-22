/**
 * @typedef {{ username: string, password: string }} Credentials
 */

/**
 * Extract and decode credentials from an HTTP Basic Authorization header.
 *
 * This is the shared logic split out from the public API: callers pass in the
 * raw credential segment (without the `Basic ` prefix) and get back the
 * username/password pair, or null if the input cannot be decoded.
 *
 * A note on the charset: per RFC 7617, HTTP Basic uses UTF-8, not
 * ISO-8859-1 (UTF-8 is backwards-compatible for ASCII credential strings).
 * The browser and tooling ecosystem has standardized on UTF-8 and we follow
 * that convention. The HTTP transport itself is 7-bit ASCII, so the base64
 * payload is byte-identical regardless of charset; the charset only matters
 * at decode time, and we decode as UTF-8.
 *
 * @param {string} encoded - The base64 credential segment.
 * @returns {Credentials|null}
 */
export function decodeBasicCredentials(encoded) {
  if (typeof encoded !== 'string') {
    return null;
  }
  let binary;
  try {
    binary = atob(encoded);
  } catch {
    return null;
  }

  // atob returns a binary string (one char per byte). If the credential
  // contains non-ASCII bytes, naive indexing would split a multi-byte
  // UTF-8 sequence across the colon boundary. Convert to a byte array first
  // so the colon search operates on raw bytes.
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }

  // Per RFC 7617, the userid and password are separated by a single COLON.
  // The password may itself contain a colon, so we split on the FIRST one.
  const colonIndex = bytes.indexOf(0x3a);
  if (colonIndex === -1) {
    return null;
  }

  const usernameBytes = bytes.subarray(0, colonIndex);
  const passwordBytes = bytes.subarray(colonIndex + 1);

  const decoder = new TextDecoder('utf-8', { fatal: false });
  const username = decoder.decode(usernameBytes);
  const password = decoder.decode(passwordBytes);

  return { username, password };
}

/**
 * Decode an HTTP Basic `Authorization` header value into username and
 * password.
 *
 * @param {string} header - The raw Authorization header value.
 * @returns {Credentials|null} The decoded credentials, or null if the
 *   header is missing, malformed, or cannot be base64-decoded.
 */
export function decodeBasicAuth(header) {
  if (typeof header !== 'string') {
    return null;
  }
  const trimmed = header.trim();
  if (trimmed.length === 0) {
    return null;
  }

  const spaceIndex = trimmed.indexOf(' ');
  const scheme = spaceIndex === -1 ? trimmed : trimmed.slice(0, spaceIndex);
  const credential = spaceIndex === -1 ? '' : trimmed.slice(spaceIndex + 1).trim();

  // RFC 7235 defines the scheme token as case-insensitive.
  if (scheme.toLowerCase() !== 'basic') {
    return null;
  }
  if (credential.length === 0) {
    return null;
  }

  return decodeBasicCredentials(credential);
}
