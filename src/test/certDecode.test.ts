import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodePemBundle, splitPemBundle, formatSummary, CertDecodeError } from '../certDecode';

// A throwaway self-signed test certificate (CN=example.test, generated
// with `openssl req -x509 -newkey rsa:2048 -nodes -days 3650`, private
// key discarded and never committed). A certificate is public data by
// design -- unlike a JWT or API key, there is nothing here worth
// treating as a secret.
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIDszCCApugAwIBAgIUEk15F4owOLyHJx4hkkRxL4uFKcQwDQYJKoZIhvcNAQEL
BQAwaTELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3Qx
JTAjBgNVBAoMHEdhcCBIdW50ZXIgTGFicyBUZXN0IEZpeHR1cmUxFTATBgNVBAMM
DGV4YW1wbGUudGVzdDAeFw0yNjA5MDcwNzAwMDdaFw0zNjA5MDQwNzAwMDdaMGkx
CzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQHDARUZXN0MSUwIwYD
VQQKDBxHYXAgSHVudGVyIExhYnMgVGVzdCBGaXh0dXJlMRUwEwYDVQQDDAxleGFt
cGxlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy6AqZdHpr
usUQmx/AlytUVAwWLhqNMWxs4r3kKMkI5fjzKPYIAtHrsgHi3XIETDlwHGT6U5/W
F5cKqeEGD7wU/mZpYB9zYPdUk1FLQtSgs5QQT3LS5x0SNnuhFmRBfDuLvfSeIcFX
3hdFoj7q3PaBxxBBgibfKLoa6HXSBSvq6IUEOGgucL/ExUiFyfkXZal6ZD2QB2pJ
OZ0/cfuKJFgIUmUKrFnwIDVbnXn1XoEzCvWrzCKer9X4/nBJKJiCom4mbZiSUZa2
CkOrcuoQyg0wiXJFB3q11oqySYNzoFokZWdxjWi9aXHIcJ8lr6QMsbK72ZVZBZNV
yuRo8Q2RjlfdAgMBAAGjUzBRMB0GA1UdDgQWBBRJHo+qNcrZQZ56v9VL/eyyC2q8
ZDAfBgNVHSMEGDAWgBRJHo+qNcrZQZ56v9VL/eyyC2q8ZDAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBPqm74FC59dDwajbTcRjnUhAVZTZu+rRuD
+0BaNhLMjoVJjXQsjB8L1OCezsUlo4HAiak2HdoCmIY6qvBBECMRVb0KHfzlv8f5
0IVv3VQ0jgOxtibyfS8Qy9nCXmRkNWbD3M9w2KCzf7FX2RBtMJfU1mhVBtxAReCj
qb4r1AoGVuP/T1mwYC64OvHGLu8oHHCYFw9fAtQmz20W3aoLbGd4tcAMR0S1gdrk
kEZbIb5U8Gia8Baz+A/9W0HgxgEVIlA+FvFWRLX7ww91cA88r8/7r3E7s3CIo3Xm
uKwhucDYQEaBXWoW5SzWg0u+qJ5ZTp0Llu8lwttF9fTKZIhK6xuq
-----END CERTIFICATE-----`;

test('splitPemBundle finds a single certificate block', () => {
  const blocks = splitPemBundle(TEST_CERT);
  assert.equal(blocks.length, 1);
});

test('splitPemBundle finds multiple certificate blocks in a bundle', () => {
  const bundle = `${TEST_CERT}\n${TEST_CERT}`;
  const blocks = splitPemBundle(bundle);
  assert.equal(blocks.length, 2);
});

test('splitPemBundle returns empty for text with no certificate', () => {
  assert.deepEqual(splitPemBundle('not a certificate'), []);
});

test('decodePemBundle extracts subject, issuer, and validity', () => {
  const [cert] = decodePemBundle(TEST_CERT);
  assert.match(cert.subject, /CN=example\.test/);
  assert.match(cert.issuer, /CN=example\.test/); // self-signed
  assert.ok(cert.validFrom instanceof Date);
  assert.ok(cert.validTo instanceof Date);
  assert.ok(cert.fingerprint256.length > 0);
});

test('decodePemBundle flags this fixture as not expired (valid until 2036)', () => {
  const [cert] = decodePemBundle(TEST_CERT);
  assert.equal(cert.isExpired, false);
  assert.equal(cert.expiresWithin30Days, false);
});

test('decodePemBundle handles a 2-certificate bundle', () => {
  const bundle = `${TEST_CERT}\n${TEST_CERT}`;
  const certs = decodePemBundle(bundle);
  assert.equal(certs.length, 2);
});

test('decodePemBundle throws CertDecodeError on non-certificate text', () => {
  assert.throws(() => decodePemBundle('nothing here'), CertDecodeError);
});

test('formatSummary includes the expiry status line', () => {
  const [cert] = decodePemBundle(TEST_CERT);
  const text = formatSummary(cert);
  assert.match(text, /Status:\s+valid/);
  assert.match(text, /Subject:/);
  assert.match(text, /SHA-256 fpr:/);
});
