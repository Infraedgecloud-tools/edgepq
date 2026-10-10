# Probe test fixtures

`cert.pem` and `key.pem` are a self-signed P-256 certificate for `CN=localhost`
and its private key, generated with:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -days 3650 -subj /CN=localhost -keyout key.pem -out cert.pem

They are test-only. The local TLS servers in `src/probe/*.test.ts` use them, and
they have no other use. The key protects nothing.
