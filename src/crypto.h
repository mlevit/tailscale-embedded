#pragma once
// The cryptographic primitives tsnet's protocols need. Tailscale's control protocol (controlbase) and WireGuard are
// both Noise_IK_25519_ChaChaPoly_BLAKE2s: X25519, ChaCha20-Poly1305, BLAKE2s, and Noise's HMAC-based HKDF over BLAKE2s.
//
// None of it is hand-written: X25519 and ChaCha20-Poly1305 are mbedTLS's (the same library on the device and on the host),
// BLAKE2s is the RFC 7693 reference algorithm (blake2s.c), and HMAC and HKDF are the RFC 2104 and Noise constructions
// on top of it. Each is checked against the RFCs' vectors and CPython's hashlib in test/crypto_test.c. DERP and disco
// add NaCl box, below.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_KEY_LEN 32       // an X25519 key, a ChaCha20-Poly1305 key, a BLAKE2s-256 hash
#define TSNET_AEAD_NONCE_LEN 12
#define TSNET_AEAD_TAG_LEN 16

// X25519 (RFC 7748): out = scalar * point. The scalar is clamped as RFC 7748 says. Returns 0, or -1 on failure or when
// the result is all zeros (a low-order point), which Noise and WireGuard must reject.
int tsnet_x25519(uint8_t out[TSNET_KEY_LEN], const uint8_t scalar[TSNET_KEY_LEN], const uint8_t point[TSNET_KEY_LEN]);

// The public key for a private one: scalar * the base point (u = 9). Returns 0 or -1.
int tsnet_x25519_public(uint8_t pub[TSNET_KEY_LEN], const uint8_t priv[TSNET_KEY_LEN]);

// ChaCha20-Poly1305 (RFC 8439). Seal writes `len` bytes of ciphertext and then the 16-byte tag to `out` (which may be
// `in`). Open checks the tag of `len` ciphertext bytes followed by the tag, and writes `len` bytes of plaintext to `out`;
// it returns -1 (and leaves `out` zeroed) if the tag is wrong. Both return 0 on success.
int tsnet_aead_seal(uint8_t *out, const uint8_t key[TSNET_KEY_LEN], const uint8_t nonce[TSNET_AEAD_NONCE_LEN],
                    const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len);
int tsnet_aead_open(uint8_t *out, const uint8_t key[TSNET_KEY_LEN], const uint8_t nonce[TSNET_AEAD_NONCE_LEN],
                    const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len);

// HMAC-BLAKE2s-256 (RFC 2104 with BLAKE2s, block 64 bytes): what Noise's HKDF uses.
void tsnet_hmac_blake2s(uint8_t out[TSNET_KEY_LEN], const uint8_t *key, size_t key_len, const uint8_t *data, size_t len);

// Noise's HKDF (the Noise Protocol Framework, section 4.3): from the chaining key and the input key material, up to three
// 32-byte outputs. A NULL output is skipped (but still computed when a later one is asked for, as the chain needs it).
void tsnet_hkdf(const uint8_t ck[TSNET_KEY_LEN], const uint8_t *ikm, size_t ikm_len, uint8_t out1[TSNET_KEY_LEN],
                uint8_t out2[TSNET_KEY_LEN], uint8_t out3[TSNET_KEY_LEN]);

// NaCl box, as golang.org/x/crypto/nacl/box: what DERP (key.NodePrivate.SealTo/OpenFrom) and disco
// (key.DiscoShared) seal with. The shared key is X25519 (mbedTLS, as above) then HSalsa20, and the box is
// XSalsa20-Poly1305 (TweetNaCl, third_party/tweetnacl). Checked against PyNaCl (libsodium) in test/crypto_test.c.
// Different from Go: an all-zero X25519 result (a low-order public key) is refused here, where box.Precompute goes on
// with it.
#define TSNET_BOX_NONCE_LEN 24
#define TSNET_BOX_TAG_LEN 16

// box.Precompute: the shared key for my private key and the peer's public key. Returns 0 or -1.
int tsnet_box_shared(uint8_t shared[TSNET_KEY_LEN], const uint8_t priv[TSNET_KEY_LEN], const uint8_t peer[TSNET_KEY_LEN]);
// box.SealAfterPrecomputation: writes the 16-byte tag and then `len` bytes of ciphertext to `out` (len + 16 bytes; it
// may not overlap `in`). Returns 0, or -1 when out of memory.
int tsnet_box_seal(uint8_t *out, const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN],
                   const uint8_t *in, size_t len);
// box.OpenAfterPrecomputation: `in` is the tag and then the ciphertext (`len` bytes in all, at least 16); writes len - 16
// bytes of plaintext to `out`, which may overlap `in`. Returns 0, or -1 if the tag is wrong (`out` is then zeroed) or out
// of memory.
int tsnet_box_open(uint8_t *out, const uint8_t shared[TSNET_KEY_LEN], const uint8_t nonce[TSNET_BOX_NONCE_LEN],
                   const uint8_t *in, size_t len);

// Zeroes secret memory in a way the compiler won't remove.
void tsnet_wipe(void *p, size_t len);
