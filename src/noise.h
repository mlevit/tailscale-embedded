#pragma once
// Tailscale's control protocol transport: the client side of control/controlbase, a Noise_IK_25519_ChaChaPoly_BLAKE2s
// handshake followed by encrypted records. Pure: it takes and gives bytes; the dial (controlhttp's HTTP upgrade) is
// another module. Every format and step is controlbase's (handshake.go, messages.go, conn.go), cited where used.
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

// messages.go
#define TSNET_NOISE_HEADER_LEN 3                         // headerLen: 1 type byte, 2 length bytes (big-endian)
#define TSNET_NOISE_INIT_LEN 101                         // initiationMessage: 2 version + 3 header + 32 + 48 + 16
#define TSNET_NOISE_RESP_LEN 51                          // responseMessage: 3 header + 32 + 16
// conn.go
#define TSNET_NOISE_MAX_MESSAGE 4096                     // maxMessageSize, header included
#define TSNET_NOISE_MAX_CIPHERTEXT (4096 - 3)            // maxCiphertextSize
#define TSNET_NOISE_MAX_PLAINTEXT (4096 - 3 - 16)        // maxPlaintextSize: 4077

typedef struct {
    uint8_t key[TSNET_KEY_LEN];
    uint64_t nonce; // the next record's counter; UINT64_MAX (invalidNonce) means exhausted
} tsnet_noise_cipher_t;

// An established connection: the client sends with tx and receives with rx (Split's c1 and c2).
typedef struct {
    tsnet_noise_cipher_t tx, rx;
} tsnet_noise_conn_t;

// A client handshake in progress.
typedef struct {
    uint8_t h[TSNET_KEY_LEN], ck[TSNET_KEY_LEN];
    uint8_t ephemeral[TSNET_KEY_LEN];   // our ephemeral private key
    uint8_t machine[TSNET_KEY_LEN];     // our machine private key
    uint8_t control_pub[TSNET_KEY_LEN]; // the control server's public key
} tsnet_noise_client_t;

// Starts a handshake (controlbase.ClientDeferred) as `version` (the capability version) with our machine key and the
// server's public key, and writes the 101-byte initiation message to send. A fresh ephemeral key is made with
// tsnet_random. Returns 0, or -1 (no randomness, or a key that gives a low-order result).
int tsnet_noise_client_start(tsnet_noise_client_t *c, const uint8_t machine_priv[TSNET_KEY_LEN],
                             const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version,
                             uint8_t init[TSNET_NOISE_INIT_LEN]);
// The same with a given ephemeral key, for tests.
int tsnet_noise_client_start_with(tsnet_noise_client_t *c, const uint8_t machine_priv[TSNET_KEY_LEN],
                                  const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version,
                                  const uint8_t ephemeral_priv[TSNET_KEY_LEN], uint8_t init[TSNET_NOISE_INIT_LEN]);

#define TSNET_NOISE_SERVER_ERROR (-2)

// Finishes the handshake (continueClientHandshake) with the server's first whole frame (header included). On success
// writes the connection's two ciphers and returns 0. Returns TSNET_NOISE_SERVER_ERROR if the server sent an error
// message instead (its text is the frame's payload), or -1 for anything else (wrong type or length, a bad tag, a
// low-order key). The handshake state is wiped either way.
int tsnet_noise_client_finish(tsnet_noise_client_t *c, const uint8_t *frame, size_t len, tsnet_noise_conn_t *conn);

// Seals one transport record (conn.go encryptLocked): writes the 3-byte header, the ciphertext and the tag to `out`
// (len + 19 bytes) and returns that length. `len` is at most TSNET_NOISE_MAX_PLAINTEXT; a longer write is the caller's
// to split. Returns 0 if the length is too big or the send nonce is exhausted.
size_t tsnet_noise_seal(tsnet_noise_conn_t *conn, uint8_t *out, const uint8_t *plaintext, size_t len);

// Opens one whole record (header included) into `plaintext` (at most len - 19 bytes) and returns its length, or -1
// for a frame that isn't a record, a length that doesn't match, a bad tag or an exhausted receive nonce.
int tsnet_noise_open(tsnet_noise_conn_t *conn, uint8_t *plaintext, const uint8_t *frame, size_t len);

void tsnet_noise_conn_wipe(tsnet_noise_conn_t *conn);

// Cuts a byte stream into frames (1 type byte, 2 length bytes, payload): feed it what the socket gave; once a whole frame
// is in, tsnet_noise_framer_frame() returns its length (its bytes are buf[0 .. length-1]) until reset. A header announcing
// more than TSNET_NOISE_MAX_MESSAGE in all is an error (conn.go refuses records over maxCiphertextSize).
typedef struct {
    uint8_t buf[TSNET_NOISE_MAX_MESSAGE];
    size_t have;
} tsnet_noise_framer_t;

// Takes bytes up to the end of one frame and returns how many it took (the rest belong to the next frame).
size_t tsnet_noise_framer_feed(tsnet_noise_framer_t *f, const uint8_t *data, size_t len);
// The buffered frame's length when it is whole, 0 while more is needed, -1 if the header is over the maximum.
int tsnet_noise_framer_frame(const tsnet_noise_framer_t *f);
// Drops the current frame, keeping nothing.
void tsnet_noise_framer_reset(tsnet_noise_framer_t *f);
