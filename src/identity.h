#pragma once
// tsnet's identity: the keys a Tailscale node keeps, in tsnet's own storage (platform.h), never another's.
//   - The machine key, made at first start and saved at once (tailscaled's _machinekey).
//   - The node key and the old node key, persist.PrivateNodeKey and OldPrivateNodeKey, which change only as doLogin
//     changes them: tsnet_identity_try_node_key picks the key a register tries, and tsnet_identity_commit_node_key keeps
//     it once the register succeeds.
//   - The NL key, persist.NetworkLockKey: an Ed25519 key (Monocypher), made when missing.
//   - The log ID: logid.PrivateID, made at first start; BackendLogID is its public ID, the hex SHA-256.
//   - The stable node ID, persist.NodeID, as the map says.
#include <stdbool.h>
#include <stdint.h>
#include "crypto.h"

typedef struct {
    uint8_t machine[TSNET_KEY_LEN];
    uint8_t node[TSNET_KEY_LEN];     // all zero until a register succeeds
    uint8_t old_node[TSNET_KEY_LEN]; // all zero when there is none
    uint8_t nl_seed[TSNET_KEY_LEN];  // the Ed25519 private key's seed
    uint8_t nl_pub[TSNET_KEY_LEN];
    uint8_t log_private[TSNET_KEY_LEN];
    char backend_log_id[2 * TSNET_KEY_LEN + 1];
    char node_id[64];
} tsnet_identity_t;

// Loads the identity, making and saving the machine key, NL key and log ID when missing. Returns 0, or -1 if the
// storage fails (an identity that can't be kept mustn't be used: each restart would be a new node).
int tsnet_identity_load(tsnet_identity_t *id);

// doLogin's choice of the key a register tries: a new one when `regen` or when there is none yet (and the current one
// becomes the old one), otherwise the current one. Writes the key to try and the old key to send (zero when none).
int tsnet_identity_try_node_key(const tsnet_identity_t *id, bool regen, uint8_t try_key[TSNET_KEY_LEN],
                                uint8_t old_key[TSNET_KEY_LEN]);
// The register succeeded (no AuthURL): the tried key is the node key, the old key kept with it. Saved. Returns 0 or -1.
int tsnet_identity_commit_node_key(tsnet_identity_t *id, const uint8_t try_key[TSNET_KEY_LEN],
                                   const uint8_t old_key[TSNET_KEY_LEN]);
// persist.NodeID from the self node; saved when it changes. Returns 0 or -1.
int tsnet_identity_set_node_id(tsnet_identity_t *id, const char *stable_id);

// key.NewNode / key.NewMachine: 32 random bytes, clamped for Curve25519 (key/node.go). Returns 0 or -1.
int tsnet_new_x25519_key(uint8_t key[TSNET_KEY_LEN]);
