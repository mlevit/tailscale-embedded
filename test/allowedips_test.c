// Host test of AllowedIPs: wireguard-go's own TestTrieIPv4 and TestTrieIPv6 (device/allowedips_test.go, the
// second ported there from the Linux kernel's selftest), then AllowedPeerSourceIP.
#include <stdio.h>
#include <string.h>
#include "allowedips.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static uint8_t A[32] = {'a'}, B[32] = {'b'}, C[32] = {'c'}, D[32] = {'d'}, E[32] = {'e'}, F[32] = {'f'},
               G[32] = {'g'}, H[32] = {'h'};
static tsnet_aips_t t;

static void ins4(const uint8_t *peer, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t bits)
{
    uint8_t ip[4] = {a, b, c, d};
    EXPECT(tsnet_aips_insert(&t, ip, false, bits, peer) == 0);
}

static bool is4(const uint8_t *peer, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t ip[4] = {a, b, c, d};
    const uint8_t *got = tsnet_aips_lookup(&t, ip, false);
    return got && memcmp(got, peer, 32) == 0;
}

static void trie_ipv4(void)
{
    tsnet_aips_init(&t);
    ins4(A, 192, 168, 4, 0, 24);
    ins4(B, 192, 168, 4, 4, 32);
    ins4(C, 192, 168, 0, 0, 16);
    ins4(D, 192, 95, 5, 64, 27);
    ins4(C, 192, 95, 5, 65, 27); // the same prefix as D's, masked: it moves to C
    ins4(E, 0, 0, 0, 0, 0);
    ins4(G, 64, 15, 112, 0, 20);
    ins4(H, 64, 15, 123, 211, 25);
    ins4(A, 10, 0, 0, 0, 25);
    ins4(B, 10, 0, 0, 128, 25);
    ins4(A, 10, 1, 0, 0, 30);
    ins4(B, 10, 1, 0, 4, 30);
    ins4(C, 10, 1, 0, 8, 29);
    ins4(D, 10, 1, 0, 16, 29);
    EXPECT(is4(A, 192, 168, 4, 20));
    EXPECT(is4(A, 192, 168, 4, 0));
    EXPECT(is4(B, 192, 168, 4, 4));
    EXPECT(is4(C, 192, 168, 200, 182));
    EXPECT(is4(C, 192, 95, 5, 68));
    EXPECT(is4(E, 192, 95, 5, 96));
    EXPECT(is4(G, 64, 15, 116, 26));
    EXPECT(is4(G, 64, 15, 127, 3));
    ins4(A, 1, 0, 0, 0, 32);
    ins4(A, 64, 0, 0, 0, 32);
    ins4(A, 128, 0, 0, 0, 32);
    ins4(A, 192, 0, 0, 0, 32);
    ins4(A, 255, 0, 0, 0, 32);
    EXPECT(is4(A, 1, 0, 0, 0) && is4(A, 64, 0, 0, 0) && is4(A, 128, 0, 0, 0) && is4(A, 192, 0, 0, 0) &&
           is4(A, 255, 0, 0, 0));
    tsnet_aips_remove_peer(&t, A);
    EXPECT(!is4(A, 1, 0, 0, 0) && !is4(A, 64, 0, 0, 0) && !is4(A, 128, 0, 0, 0) && !is4(A, 192, 0, 0, 0) &&
           !is4(A, 255, 0, 0, 0));
    const uint8_t *all[] = {A, B, C, D, E, G, H};
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        tsnet_aips_remove_peer(&t, all[i]);
    }
    EXPECT(t.n == 0); // removing every peer empties the table
    ins4(A, 192, 168, 0, 0, 16);
    ins4(A, 192, 168, 0, 0, 24);
    tsnet_aips_remove_peer(&t, A);
    EXPECT(!is4(A, 192, 168, 0, 1));
    tsnet_aips_free(&t);
}

static void v6(uint8_t out[16], uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    uint32_t w[4] = {a, b, c, d};
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)(w[i] >> 24);
        out[4 * i + 1] = (uint8_t)(w[i] >> 16);
        out[4 * i + 2] = (uint8_t)(w[i] >> 8);
        out[4 * i + 3] = (uint8_t)w[i];
    }
}

static void ins6(const uint8_t *peer, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint8_t bits)
{
    uint8_t ip[16];
    v6(ip, a, b, c, d);
    EXPECT(tsnet_aips_insert(&t, ip, true, bits, peer) == 0);
}

static bool is6(const uint8_t *peer, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    uint8_t ip[16];
    v6(ip, a, b, c, d);
    const uint8_t *got = tsnet_aips_lookup(&t, ip, true);
    return got && memcmp(got, peer, 32) == 0;
}

static void trie_ipv6(void)
{
    tsnet_aips_init(&t);
    ins6(D, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
    ins6(C, 0x26075300, 0x60006b00, 0, 0, 64);
    ins6(E, 0, 0, 0, 0, 0);
    ins6(F, 0, 0, 0, 0, 0); // ::/0 moves to F
    ins6(G, 0x24046800, 0, 0, 0, 32);
    ins6(H, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64);
    ins6(A, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128);
    ins6(C, 0x24446800, 0x40e40800, 0xdeaebeef, 0xdefbeef, 128);
    ins6(B, 0x24446800, 0xf0e40800, 0xeeaebeef, 0, 98);
    EXPECT(is6(D, 0x26075300, 0x60006b00, 0, 0xc05f0543));
    EXPECT(is6(C, 0x26075300, 0x60006b00, 0, 0xc02e01ee));
    EXPECT(is6(F, 0x26075300, 0x60006b01, 0, 0));
    EXPECT(is6(G, 0x24046800, 0x40040806, 0, 0x1006));
    EXPECT(is6(G, 0x24046800, 0x40040806, 0x1234, 0x5678));
    EXPECT(is6(F, 0x240467ff, 0x40040806, 0x1234, 0x5678));
    EXPECT(is6(F, 0x24046801, 0x40040806, 0x1234, 0x5678));
    EXPECT(is6(H, 0x24046800, 0x40040800, 0x1234, 0x5678));
    EXPECT(is6(H, 0x24046800, 0x40040800, 0, 0));
    EXPECT(is6(H, 0x24046800, 0x40040800, 0x10101010, 0x10101010));
    EXPECT(is6(A, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef));
    // An IPv4 address never matches an IPv6 prefix, ::/0 included.
    uint8_t ip4[4] = {10, 0, 0, 1};
    EXPECT(tsnet_aips_lookup(&t, ip4, false) == NULL);
    tsnet_aips_free(&t);
}

// AllowedPeerSourceIP: a peer's own prefixes, and nothing else, may be its packets' source.
static void allowed(void)
{
    tsnet_aips_init(&t);
    ins4(A, 100, 64, 0, 1, 32);  // A's tailnet address
    ins4(B, 100, 64, 0, 2, 32);  // B's
    ins4(B, 192, 168, 7, 0, 24); // a subnet B routes
    uint8_t a_ip[4] = {100, 64, 0, 1}, b_ip[4] = {100, 64, 0, 2}, sub[4] = {192, 168, 7, 9}, other[4] = {8, 8, 8, 8};
    EXPECT(tsnet_aips_allowed(&t, A, a_ip, false) && !tsnet_aips_allowed(&t, A, b_ip, false));
    EXPECT(tsnet_aips_allowed(&t, B, sub, false) && !tsnet_aips_allowed(&t, A, sub, false));
    EXPECT(!tsnet_aips_allowed(&t, A, other, false) && !tsnet_aips_allowed(&t, B, other, false));
    uint8_t bad[4] = {1, 2, 3, 4};
    EXPECT(tsnet_aips_insert(&t, bad, false, 33, A) == -1); // a length past the address
    // The longest match decides (Lookup(src) != peer drops): a peer holding 0.0.0.0/0, as an exit node's AllowedIPs
    // do, may send as an address nobody holds more narrowly, but never as another peer's.
    ins4(H, 0, 0, 0, 0, 0);
    EXPECT(!tsnet_aips_allowed(&t, H, a_ip, false) && !tsnet_aips_allowed(&t, H, sub, false));
    EXPECT(tsnet_aips_allowed(&t, H, other, false) && tsnet_aips_allowed(&t, A, a_ip, false));
    tsnet_aips_free(&t);
}

int main(void)
{
    trie_ipv4();
    trie_ipv6();
    allowed();
    if (failures == 0) {
        printf("tsnet allowedips_test: ok\n");
    }
    return failures != 0;
}
