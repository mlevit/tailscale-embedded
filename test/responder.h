#pragma once
// A controlbase responder for tsnet's host tests, written separately from the client, from the public
// primitives, following the server side of control/controlbase (Server in handshake.go: the mirror of the client's
// IK steps), so a mistake on either side shows as a mismatch.
#include <stdio.h>
#include <string.h>
#include "blake2s.h"
#include "crypto.h"
#include "noise.h"

typedef struct {
    uint8_t h[32], ck[32];
} sym_t;

static void s_init(sym_t *s, uint16_t version, const uint8_t control_pub[32])
{
    static const char NAME[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
    tsnet_blake2s(s->h, 32, NULL, 0, NAME, strlen(NAME));
    memcpy(s->ck, s->h, 32);
    char prologue[64];
    int n = snprintf(prologue, sizeof prologue, "Tailscale Control Protocol v%u", (unsigned)version);
    tsnet_blake2s_t b;
    tsnet_blake2s_init(&b, 32, NULL, 0);
    tsnet_blake2s_update(&b, s->h, 32);
    tsnet_blake2s_update(&b, prologue, (size_t)n);
    tsnet_blake2s_final(&b, s->h);
    tsnet_blake2s_init(&b, 32, NULL, 0);
    tsnet_blake2s_update(&b, s->h, 32);
    tsnet_blake2s_update(&b, control_pub, 32);
    tsnet_blake2s_final(&b, s->h);
}

static void s_mix_hash(sym_t *s, const uint8_t *d, size_t len)
{
    tsnet_blake2s_t b;
    tsnet_blake2s_init(&b, 32, NULL, 0);
    tsnet_blake2s_update(&b, s->h, 32);
    tsnet_blake2s_update(&b, d, len);
    tsnet_blake2s_final(&b, s->h);
}

static int s_mix_dh(sym_t *s, const uint8_t priv[32], const uint8_t pub[32], uint8_t k[32])
{
    uint8_t dh[32];
    if (tsnet_x25519(dh, priv, pub) != 0) {
        return -1;
    }
    tsnet_hkdf(s->ck, dh, 32, s->ck, k, NULL);
    return 0;
}

static const uint8_t ZERO_NONCE[12] = {0};

// Server: process the initiation, write the response. Returns 0 and the client's machine key, or -1.
static int serve(uint16_t version, const uint8_t control_priv[32], const uint8_t server_eph[32], const uint8_t *init,
                 uint8_t resp[51], uint8_t machine_pub[32], tsnet_noise_conn_t *server_conn)
{
    uint8_t control_pub[32], k[32];
    tsnet_x25519_public(control_pub, control_priv);
    sym_t s;
    s_init(&s, version, control_pub);
    if (init[0] != (version >> 8) || init[1] != (version & 0xff) || init[2] != 1 || init[3] != 0 || init[4] != 96) {
        return -1;
    }
    const uint8_t *client_eph = init + 5;
    s_mix_hash(&s, client_eph, 32);
    if (s_mix_dh(&s, control_priv, client_eph, k) != 0) {
        return -1;
    }
    if (tsnet_aead_open(machine_pub, k, ZERO_NONCE, s.h, 32, init + 37, 32) != 0) {
        return -1;
    }
    s_mix_hash(&s, init + 37, 48);
    if (s_mix_dh(&s, control_priv, machine_pub, k) != 0) {
        return -1;
    }
    if (tsnet_aead_open(NULL, k, ZERO_NONCE, s.h, 32, init + 85, 0) != 0) {
        return -1;
    }
    s_mix_hash(&s, init + 85, 16);

    resp[0] = 2;
    resp[1] = 0;
    resp[2] = 48;
    tsnet_x25519_public(resp + 3, server_eph);
    s_mix_hash(&s, resp + 3, 32);
    if (s_mix_dh(&s, server_eph, client_eph, k) != 0 || s_mix_dh(&s, server_eph, machine_pub, k) != 0) {
        return -1;
    }
    tsnet_aead_seal(resp + 35, k, ZERO_NONCE, s.h, 32, NULL, 0);
    s_mix_hash(&s, resp + 35, 16);
    // Split: the server receives with c1 and sends with c2.
    tsnet_hkdf(s.ck, NULL, 0, server_conn->rx.key, server_conn->tx.key, NULL);
    server_conn->rx.nonce = server_conn->tx.nonce = 0;
    return 0;
}
