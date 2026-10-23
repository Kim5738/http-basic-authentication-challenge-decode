import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decodeBasicAuth, decodeBasicCredentials } from '../src/core.js';

test('decodes a standard ASCII credential pair', () => {
  // 'alice:secret' -> YWxpY2U6c2VjcmV0
  const result = decodeBasicAuth('Basic YWxpY2U6c2VjcmV0');
  assert.deepStrictEqual(result, { username: 'alice', password: 'secret' });
});

test('decodes an empty password', () => {
  // 'alice:' -> YWxpY2U6
  const result = decodeBasicAuth('Basic YWxpY2U6');
  assert.deepStrictEqual(result, { username: 'alice', password: '' });
});

test('decodes an empty username', () => {
  // ':secret' -> OnNlY3JldA==
  const result = decodeBasicAuth('Basic OnNlY3JldA==');
  assert.deepStrictEqual(result, { username: '', password: 'secret' });
});

test('decodes a password containing a colon', () => {
  // 'alice:pass:word' -> YWxpY2U6cGFzczp3b3Jk
  const result = decodeBasicAuth('Basic YWxpY2U6cGFzczp3b3Jk');
  assert.deepStrictEqual(result, { username: 'alice', password: 'pass:word' });
});

test('returns null when no colon separates credentials', () => {
  // 'alice' (no colon) -> YWxpY2U=
  const result = decodeBasicAuth('Basic YWxpY2U=');
  assert.strictEqual(result, null);
});

test('returns null for a non-Basic scheme', () => {
  // 'Bearer' with 'alice:secret' payload
  const result = decodeBasicAuth('Bearer YWxpY2U6c2VjcmV0');
  assert.strictEqual(result, null);
});

test('accepts a lowercase scheme token', () => {
  const result = decodeBasicAuth('basic YWxpY2U6c2VjcmV0');
  assert.deepStrictEqual(result, { username: 'alice', password: 'secret' });
});

test('accepts a mixed-case scheme token', () => {
  const result = decodeBasicAuth('BaSiC YWxpY2U6c2VjcmV0');
  assert.deepStrictEqual(result, { username: 'alice', password: 'secret' });
});

test('tolerates extra whitespace around the credential', () => {
  const result = decodeBasicAuth('Basic   YWxpY2U6c2VjcmV0  ');
  assert.deepStrictEqual(result, { username: 'alice', password: 'secret' });
});

test('returns null when the header is an empty string', () => {
  assert.strictEqual(decodeBasicAuth(''), null);
});

test('returns null when the header is only the scheme', () => {
  assert.strictEqual(decodeBasicAuth('Basic'), null);
});

test('returns null when the base64 is invalid', () => {
  // 'Basic !@#$' is not valid base64
  assert.strictEqual(decodeBasicAuth('Basic !@#$'), null);
});

test('decodes UTF-8 multi-byte credentials', () => {
  // 'alice:héllo' encoded in UTF-8 base64
  // Buffer.from('alice:héllo', 'utf8').toString('base64') -> YWxpY2U6aMOpbGxv
  const result = decodeBasicAuth('Basic YWxpY2U6aMOpbGxv');
  assert.deepStrictEqual(result, { username: 'alice', password: 'héllo' });
});

test('decodeBasicCredentials works standalone', () => {
  const result = decodeBasicCredentials('YWxpY2U6c2VjcmV0');
  assert.deepStrictEqual(result, { username: 'alice', password: 'secret' });
});

test('decodeBasicCredentials returns null for non-string input', () => {
  assert.strictEqual(decodeBasicCredentials(123), null);
  assert.strictEqual(decodeBasicCredentials(undefined), null);
  assert.strictEqual(decodeBasicCredentials(null), null);
});
