# HTTPS test identity

`https-identity.p12` contains a public, test-only RSA key and a self-signed certificate for
`wrong.example`, with an empty archive password. Never use it outside tests. The loopback HTTPS
test connects to `127.0.0.1`, checking that discovery accepts both an untrusted issuer and a
hostname mismatch. PKCS#12 avoids Wine's unimplemented PKCS#8 decoder. The certificate has a
100-year lifetime so server-side expiry checks do not prevent the handshake under test.

To regenerate from the repository root using OpenSSL:

```sh
work=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -noenc -sha256 -days 36500 \
  -subj '/CN=wrong.example' -addext 'subjectAltName=DNS:wrong.example' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$work/key.pem" -out "$work/cert.pem"
openssl pkcs12 -export -in "$work/cert.pem" -inkey "$work/key.pem" \
  -passout pass: -out src/protocols/fixtures/https-identity.p12
rm -r "$work"
```
