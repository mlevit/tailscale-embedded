# TweetNaCl (vendored)

A one-file crypto library by NaCl's authors (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers), used only for
NaCl box's HSalsa20 and XSalsa20-Poly1305 (`crypto_core_hsalsa20`, `crypto_secretbox`, `crypto_secretbox_open`). That is
the box DERP seals its handshake with (`key.NodePrivate.SealTo`, Go's `golang.org/x/crypto/nacl/box`) and the one disco
seals its messages with. Neither mbedTLS 3.6 nor Monocypher 4 has Salsa20. The X25519 step of the box stays mbedTLS's
(`tsnet_box_shared` in `src/crypto.c`), so TweetNaCl's own field arithmetic isn't called.

- **Source:** TweetNaCl **20140427**, the newest release, from https://tweetnacl.cr.yp.to/20140427/ (`tweetnacl.c`,
  `tweetnacl.h`). The site publishes no checksums. Both files match the SHA-512 and sizes that pkgsrc's
  `security/TweetNaCl/distinfo` records (`tweetnacl.c` `3eeff767e62de5d5…`, 16,637 bytes; `tweetnacl.h`
  `3256811a72c2d1a0…`, 20,014 bytes).
- **Copied unmodified:** `src/tweetnacl.{c,h}`. It is public domain. No local patches. `src/crypto.c` supplies the
  `randombytes` it needs to link (only its key-pair functions call it, and this project doesn't).
- The box is checked against PyNaCl (libsodium) at 18 lengths, with every byte of each box changed
  (`test/crypto_test.c`, vectors from `tools/box_vectors.py`).
