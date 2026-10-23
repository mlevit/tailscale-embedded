// tsnet's identity. See identity.h.
#include "identity.h"
#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "monocypher-ed25519.h"
#include "platform.h"

// Storage names (at most 15 characters).
#define S_MACHINE "machine"
#define S_NODE "node"
#define S_OLD_NODE "old_node"
#define S_NL "nl"
#define S_LOG "log_id"
#define S_NODE_ID "node_id"

static const uint8_t ZERO[TSNET_KEY_LEN];

int tsnet_new_x25519_key(uint8_t key[TSNET_KEY_LEN])
{
    if (tsnet_random(key, TSNET_KEY_LEN) != 0) {
        return -1;
    }
    key[0] &= 248; // key/node.go clamp
    key[31] = (key[31] & 127) | 64;
    return 0;
}

// Reads a 32-byte value: 0 found, 1 absent, -1 a storage error or a value of the wrong length. A bad stored key is an
// error, never "absent": tailscaled won't start on an unreadable machine key rather than quietly become a new machine
// (ipnlocal initMachineKeyLocked).
static int load_key(const char *name, uint8_t out[TSNET_KEY_LEN])
{
    uint8_t buf[TSNET_KEY_LEN];
    size_t len = 0;
    int r = tsnet_store_get(name, buf, sizeof buf, &len);
    memset(out, 0, TSNET_KEY_LEN);
    if (r == 0 && len == TSNET_KEY_LEN) {
        memcpy(out, buf, TSNET_KEY_LEN);
    }
    tsnet_wipe(buf, sizeof buf); // a private key's copy on the stack
    if (r == 1) {
        return 1;
    }
    if (r != 0 || len != TSNET_KEY_LEN) {
        tsnet_log(TSNET_LOG_ERROR, "identity: the stored %s key can't be read", name);
        return -1;
    }
    return 0;
}

// Loads a key, or makes one with `make` and saves it. Returns 0 or -1.
static int load_or_make(const char *name, uint8_t out[TSNET_KEY_LEN], int (*make)(uint8_t *))
{
    int r = load_key(name, out);
    if (r == 0) {
        return 0;
    }
    if (r < 0 || make(out) != 0 || tsnet_store_set(name, out, TSNET_KEY_LEN) != 0) {
        tsnet_log(TSNET_LOG_ERROR, "identity: can't keep the %s key", name);
        return -1;
    }
    tsnet_log(TSNET_LOG_INFO, "identity: made a new %s key", name);
    return 0;
}

static int random_bytes(uint8_t *out)
{
    return tsnet_random(out, TSNET_KEY_LEN);
}

int tsnet_identity_load(tsnet_identity_t *id)
{
    memset(id, 0, sizeof *id);
    if (load_or_make(S_MACHINE, id->machine, tsnet_new_x25519_key) != 0 ||
        load_or_make(S_NL, id->nl_seed, random_bytes) != 0 || load_or_make(S_LOG, id->log_private, random_bytes) != 0) {
        return -1;
    }
    if (load_key(S_NODE, id->node) < 0 || load_key(S_OLD_NODE, id->old_node) < 0) {
        return -1;
    }
    size_t len = 0;
    int r = tsnet_store_get(S_NODE_ID, id->node_id, sizeof id->node_id - 1, &len);
    id->node_id[r == 0 ? len : 0] = '\0';
    if (r < 0) {
        id->node_id[0] = '\0'; // a bad value is just unknown until the next map
    }
    // key.TLPrivate is Go's ed25519 key: the public half from the seed (RFC 8032). Monocypher wipes the seed it's given.
    uint8_t seed[TSNET_KEY_LEN], secret[64];
    memcpy(seed, id->nl_seed, sizeof seed);
    crypto_ed25519_key_pair(secret, id->nl_pub, seed);
    tsnet_wipe(secret, sizeof secret);
    // logid.PrivateID.Public: SHA-256 of the private ID; its text is lowercase hex.
    uint8_t pub[32];
    mbedtls_sha256(id->log_private, TSNET_KEY_LEN, pub, 0);
    for (int i = 0; i < 32; i++) {
        snprintf(id->backend_log_id + 2 * i, 3, "%02x", pub[i]);
    }
    return 0;
}

int tsnet_identity_try_node_key(const tsnet_identity_t *id, bool regen, uint8_t try_key[TSNET_KEY_LEN],
                                uint8_t old_key[TSNET_KEY_LEN])
{
    bool none = memcmp(id->node, ZERO, TSNET_KEY_LEN) == 0;
    if (regen || none) {
        // "Generating a new nodekey.": persist.OldPrivateNodeKey = persist.PrivateNodeKey
        memcpy(old_key, id->node, TSNET_KEY_LEN);
        return tsnet_new_x25519_key(try_key);
    }
    memcpy(try_key, id->node, TSNET_KEY_LEN); // "Try refreshing the current key first"
    memcpy(old_key, id->old_node, TSNET_KEY_LEN);
    return 0;
}

int tsnet_identity_commit_node_key(tsnet_identity_t *id, const uint8_t try_key[TSNET_KEY_LEN],
                                   const uint8_t old_key[TSNET_KEY_LEN])
{
    if (tsnet_store_set(S_NODE, try_key, TSNET_KEY_LEN) != 0 || tsnet_store_set(S_OLD_NODE, old_key, TSNET_KEY_LEN) != 0) {
        return -1;
    }
    memcpy(id->node, try_key, TSNET_KEY_LEN);
    memcpy(id->old_node, old_key, TSNET_KEY_LEN);
    return 0;
}

int tsnet_identity_set_node_id(tsnet_identity_t *id, const char *stable_id)
{
    if (strcmp(id->node_id, stable_id) == 0) {
        return 0;
    }
    if (tsnet_store_set(S_NODE_ID, stable_id, strlen(stable_id)) != 0) {
        return -1;
    }
    snprintf(id->node_id, sizeof id->node_id, "%s", stable_id);
    return 0;
}
