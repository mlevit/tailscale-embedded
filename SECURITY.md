# Security

## Reporting a vulnerability

Report it privately through GitHub's **Report a vulnerability** button on this repository's Security tab. Please don't
open a public issue. You'll get an answer within a week.

A vulnerability in Tailscale's own software or service goes to Tailscale: https://tailscale.com/security.

## What's in scope

Everything that parses or acts on input from the network: control's JSON and zstd, HTTP/2, Noise, DERP frames, disco,
STUN, WireGuard and the IP packets behind it, and the packet filter. Also key handling and key storage.

## How it's built

- Every parser of network input is bounded, and its tests cover every split point, truncation and garbage, under
  ASan and UBSan. `test/fuzz_test.c` runs a mutation fuzzer over STUN, HTTP/1, the packet filter and WireGuard receive.
- JSON is refused before parsing if it nests deeper than 32 levels (cJSON recurses).
- No hand-written crypto: X25519 and ChaCha20-Poly1305 are mbedTLS's, Ed25519 is Monocypher's, and NaCl box is
  TweetNaCl's. BLAKE2s, HMAC and HKDF follow RFC 7693, RFC 2104 and the Noise specification, checked against their
  test vectors.
- A WireGuard packet's source address must belong to the peer that sent it, by longest match, as in wireguard-go.

## What the user must do

- **Keys at rest.** On ESP-IDF the node's keys are in NVS, in plaintext. Anyone with the flash can read them and act
  as the node. Turn on flash encryption and NVS encryption on any device that leaves your hands.
- **Auth keys.** An auth key built into an image is in the image. Treat such an image as a secret, prefer a one-off,
  tagged, pre-approved key, and build release images without one: a node that's registered logs in with its stored
  key.
- **The clock** must be right before the node starts (SNTP): TLS checks certificate dates.

## Known gaps

These are open:

- **Map sizes aren't capped for the device.** A compromised control server can make the node allocate megabytes
  (decoded map messages, the zstd window, the JSON tree, peers). tsnet handles the allocation failures, but the
  device's other tasks can starve.
- **CallMeMaybe targets aren't filtered.** Any tailnet peer can make the node send disco pings to up to 16 addresses
  of its choice, with no rate limit. The official client does the same (it filters only IPv6 link-local).
- **A peer's endpoint table can be filled.** A captured disco ping replayed from spoofed sources fills a peer's 16
  endpoint slots for 45 s, so the path stays on DERP. The official client holds 100 and always admits the netmap's
  endpoints.
- **WireGuard's under-load cookie path isn't implemented.** Anyone with the node's public key can send handshake
  initiations, and each costs an X25519 operation in the event loop.
- **Not implemented:** IPv6 and tailnet lock (the node sends an NL key but signs nothing).
