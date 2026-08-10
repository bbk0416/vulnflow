# VulnFlow 72.0.51 — Authorized external-validation operator

SQLite schema remains 46.

This release closes an operator-substitution boundary in the signed external
validation exchange. Earlier challenges authenticated the requester, source,
target, checks, parameters, nonce, and collection window, but did not state
which operator signing key was authorized to answer. Different operator keys
could therefore create independently valid responses to the same challenge if
a verifier was given the corresponding public key out of band.

72.0.51 adds the authorized operator Ed25519 key ID and public-key fingerprint
to request format v2, request-binding format v2, response format v4, and
runner-kit format v2. The requester signature covers that identity.

The response signer and runner-kit execution path now reject a private key that
does not match the signed authorization before creating response output or
starting the external-validation child process. The detached verifier checks
that the pinned operator public key, embedded operator key, response statement,
and signed request authorization all identify the same key.

The public core contract increases from 579 to 585 tests. Three Chromium E2E
tests remain outside the core count. No product workflow or database schema was
added.
