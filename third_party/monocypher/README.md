# Monocypher (vendored)

A small, audited crypto library, used only for Ed25519 (RFC 8032, with SHA-512): the NL key (`key.NLPrivate`, Go's
`crypto/ed25519`) that the official client puts in every `RegisterRequest`. mbedTLS 3.6 doesn't implement Ed25519.

- **Source:** Monocypher **4.0.3**, `monocypher-4.0.3.tar.gz`. Its SHA-512
  `40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965`
  is the one monocypher.org publishes; the copy from monocypher.org and the GitHub release asset are identical.
- **Copied unmodified:** `src/monocypher.{c,h}`, `src/optional/monocypher-ed25519.{c,h}` and `LICENCE.md` (BSD
  2-clause or CC0; this project takes BSD). No local patches.
- 4.0.3 fixes a timing leak in EdDSA signing. Monocypher was audited by Cure53 (2020). This project only makes a key
  pair: it signs nothing until tailnet lock is supported.
