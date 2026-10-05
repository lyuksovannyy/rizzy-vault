# TLS test fixtures for `rv`

Test-only certificates and keys for the loopback TLS tests of `rv` ([ADR 0030](../../../../../docs/adr/0030-client-tls-rv.md) Decision 7 and open question 5): `crates/rizzy-cli/tests/tls.rs` and the TLS test of `crates/rizzy-cli/tests/e2e.rs`. **They protect nothing.** The private keys are public by being here; never use any of these files outside these tests.

They were generated once, on 2026-10-05, with the system OpenSSL CLI (OpenSSL 3.6.2), outside the build. No crate generates certificates at test time: `rcgen` would be another crypto crate under ADR 0009 (ADR 0030 open question 5). Every key is ECDSA P-256 in PKCS#8; every signature is ECDSA with SHA-256. Validity is 100 years from 2026-10-05, except for `expired.pem`.

| File | What it is | Used for |
|---|---|---|
| `ca.pem` | The test CA: self-signed, `CA:TRUE` (critical), key usage `keyCertSign`, `cRLSign`. Its key was deleted after signing: nothing needs it | The `--ca-file` of the tests |
| `leaf.pem`, `leaf.key` | A server certificate issued by the CA: `CA:FALSE`, `serverAuth`, SAN `localhost`, `127.0.0.1`, `::1` | The handshake that succeeds; refused under the public roots |
| `expired.pem` | The same key and names, issued by the CA, valid 2000-01-01 to 2001-01-01 only | Refusal of an expired certificate (served with `leaf.key`) |
| `wrong-host.pem` | The same key, issued by the CA, SAN `wrong.example` only | Refusal of a wrong host name (served with `leaf.key`) |
| `self-signed.pem`, `self-signed.key` | A self-signed server certificate with `CA:TRUE`, SAN `localhost`, `127.0.0.1`, `::1` | Refusal when it is both the CA file and the server certificate (ADR 0030 Decision 5) |
| `self-signed-leaf.pem`, `self-signed-leaf.key` | A self-signed server certificate with `CA:FALSE` (critical), `serverAuth`, SAN `localhost`, `127.0.0.1`, `::1`; added on 2026-10-05 with the same OpenSSL | Refusal of a non-CA certificate in the CA file, which would otherwise act as a pin (ADR 0030 Decision 5) |

## How they were made

Run from this directory; `$W` is a scratch directory outside the repository.

```sh
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
leafext() {
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n' "$1" > "$W/ext.cnf"
}

# The CA (its key is deleted at the end).
key ca.key
openssl req -x509 -new -key ca.key -sha256 -days 36500 -subj "/CN=rizzy-vault test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out ca.pem

# The leaf for localhost, 127.0.0.1 and ::1.
key leaf.key
leafext "DNS:localhost,IP:127.0.0.1,IP:::1"
openssl req -new -key leaf.key -subj "/CN=localhost" -out "$W/leaf.csr"
openssl x509 -req -in "$W/leaf.csr" -CA ca.pem -CAkey ca.key -set_serial 2 -sha256 -days 36500 \
  -extfile "$W/ext.cnf" -out leaf.pem

# The expired leaf: same request, valid in 2000 only.
openssl x509 -req -in "$W/leaf.csr" -CA ca.pem -CAkey ca.key -set_serial 3 -sha256 \
  -not_before 20000101000000Z -not_after 20010101000000Z -extfile "$W/ext.cnf" -out expired.pem

# The wrong-host leaf.
leafext "DNS:wrong.example"
openssl req -new -key leaf.key -subj "/CN=wrong.example" -out "$W/wrong.csr"
openssl x509 -req -in "$W/wrong.csr" -CA ca.pem -CAkey ca.key -set_serial 4 -sha256 -days 36500 \
  -extfile "$W/ext.cnf" -out wrong-host.pem

# The self-signed CA:TRUE server certificate.
key self-signed.key
openssl req -x509 -new -key self-signed.key -sha256 -days 36500 -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -out self-signed.pem

# The self-signed CA:FALSE server certificate.
key self-signed-leaf.key
openssl req -x509 -new -key self-signed-leaf.key -sha256 -days 36500 -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -out self-signed-leaf.pem

rm ca.key
```

Regenerating them is a reviewed change like any other test-vector change: run the commands above, and check with `openssl x509 -in <file> -noout -text` that each certificate is what the table says.
