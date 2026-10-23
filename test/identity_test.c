// Host test of tsnet's identity and storage, in a temporary $TSNET_STATE_DIR, under ASan and UBSan. The known
// answers: RFC 8032's first Ed25519 vector, and Python's SHA-256 of 32 zero bytes.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _DEFAULT_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "identity.h"
#include "platform.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static void unhex(uint8_t *out, const char *hex)
{
    for (size_t i = 0; hex[2 * i]; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static const uint8_t ZERO[32];

int main(void)
{
    char dir[] = "/tmp/tsnet-identity-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        printf("no temp dir\n");
        return 1;
    }
    setenv("TSNET_STATE_DIR", dir, 1);

    // First start: the machine key, NL key and log ID are made and kept; no node key yet.
    tsnet_identity_t a, b;
    EXPECT(tsnet_identity_load(&a) == 0);
    EXPECT(memcmp(a.machine, ZERO, 32) != 0 && (a.machine[0] & 7) == 0 && (a.machine[31] & 0xc0) == 0x40); // clamped
    EXPECT(memcmp(a.node, ZERO, 32) == 0 && memcmp(a.old_node, ZERO, 32) == 0 && a.node_id[0] == '\0');
    EXPECT(strlen(a.backend_log_id) == 64);
    // Second start: the same identity.
    EXPECT(tsnet_identity_load(&b) == 0);
    EXPECT(memcmp(a.machine, b.machine, 32) == 0 && memcmp(a.nl_pub, b.nl_pub, 32) == 0 &&
           strcmp(a.backend_log_id, b.backend_log_id) == 0);

    // The known answers, through the store.
    uint8_t seed[32], want[32];
    unhex(seed, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    unhex(want, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    EXPECT(tsnet_store_set("nl", seed, 32) == 0 && tsnet_store_set("log_id", ZERO, 32) == 0);
    EXPECT(tsnet_identity_load(&a) == 0 && memcmp(a.nl_pub, want, 32) == 0 && memcmp(a.nl_seed, seed, 32) == 0);
    EXPECT(strcmp(a.backend_log_id, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925") == 0);

    // doLogin's node keys: none yet, so a new one is tried with no old key; committed, it's kept across a restart.
    uint8_t try1[32], old1[32], try2[32], old2[32];
    EXPECT(tsnet_identity_try_node_key(&a, false, try1, old1) == 0 && memcmp(try1, ZERO, 32) != 0 &&
           memcmp(old1, ZERO, 32) == 0);
    EXPECT(tsnet_identity_load(&b) == 0 && memcmp(b.node, ZERO, 32) == 0); // not kept before the commit
    EXPECT(tsnet_identity_commit_node_key(&a, try1, old1) == 0);
    EXPECT(tsnet_identity_load(&b) == 0 && memcmp(b.node, try1, 32) == 0 && memcmp(b.old_node, ZERO, 32) == 0);
    // Refresh: the current key again.
    EXPECT(tsnet_identity_try_node_key(&b, false, try2, old2) == 0 && memcmp(try2, try1, 32) == 0);
    // Regen: a new key, the current one becoming the old one.
    EXPECT(tsnet_identity_try_node_key(&b, true, try2, old2) == 0 && memcmp(try2, try1, 32) != 0 &&
           memcmp(old2, try1, 32) == 0);
    EXPECT(tsnet_identity_commit_node_key(&b, try2, old2) == 0);
    EXPECT(tsnet_identity_load(&a) == 0 && memcmp(a.node, try2, 32) == 0 && memcmp(a.old_node, try1, 32) == 0);

    // The stable node ID.
    EXPECT(tsnet_identity_set_node_id(&a, "nX7aBcDEF11CNTRL") == 0);
    EXPECT(tsnet_identity_load(&b) == 0 && strcmp(b.node_id, "nX7aBcDEF11CNTRL") == 0);

    // A stored key of the wrong length is an error, not a reason to become a new machine.
    EXPECT(tsnet_store_set("machine", "short", 5) == 0 && tsnet_identity_load(&a) == -1);

    // The store: absent, too long for the buffer, a name that isn't a plain word.
    size_t len;
    uint8_t buf[4];
    EXPECT(tsnet_store_get("nothing", buf, sizeof buf, &len) == 1);
    EXPECT(tsnet_store_set("big", "123456", 6) == 0 && tsnet_store_get("big", buf, sizeof buf, &len) == -1);
    EXPECT(tsnet_store_set("../escape", "x", 1) == -1 && tsnet_store_set("waytoolongname16", "x", 1) == -1);

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    EXPECT(system(cmd) == 0);
    if (failures == 0) {
        printf("tsnet identity_test: ok\n");
    }
    return failures != 0;
}
