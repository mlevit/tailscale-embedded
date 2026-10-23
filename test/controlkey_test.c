// Host test of tsnet's control key parser, on the real response of controlplane.tailscale.com/key?v=131
// (fetched 2026-10-23) and the ways it can be wrong.
#include <stdio.h>
#include <string.h>
#include "controlkey.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static int parse(const char *s, uint8_t pub[32])
{
    return tsnet_control_key_parse(s, strlen(s), pub);
}

int main(void)
{
    static const char REAL[] = "{\n\t\"legacyPublicKey\": \"mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970\",\n"
                               "\t\"publicKey\": \"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"\n}";
    static const uint8_t WANT[32] = {0x7d, 0x27, 0x92, 0xf9, 0xc9, 0x8d, 0x75, 0x3d, 0x20, 0x42, 0x47,
                                     0x15, 0x36, 0x80, 0x19, 0x49, 0x10, 0x4c, 0x24, 0x7f, 0x95, 0xea,
                                     0xc7, 0x70, 0xf8, 0xfb, 0x32, 0x15, 0x95, 0xe2, 0x17, 0x3b};
    uint8_t pub[32];
    EXPECT(parse(REAL, pub) == 0 && memcmp(pub, WANT, 32) == 0);
    // Upper-case hex is accepted, as Go's hex.Decode does.
    EXPECT(parse("{\"publicKey\":\"mkey:7D2792F9C98D753D2042471536801949104C247F95EAC770F8FB321595E2173B\"}", pub) == 0 &&
           memcmp(pub, WANT, 32) == 0);

    static const char *BAD[] = {
        "",                                     // empty
        "mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970", // the old pre-JSON form: legacy key only
        "{\"legacyPublicKey\":\"mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970\"}", // no Noise key
        "{\"publicKey\":\"mkey:0000000000000000000000000000000000000000000000000000000000000000\"}",       // zero
        "{\"publicKey\":\"nodekey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"}",    // wrong prefix
        "{\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173\"}",        // 63 digits
        "{\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173bb\"}",      // 65 digits
        "{\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173g\"}",       // not hex
        "{\"publicKey\":7}",                                                                               // not a string
        "{\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"",        // cut short
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        EXPECT(parse(BAD[i], pub) == -1);
    }
    // The length bounds the parse: the same text with the closing brace outside `len` is refused.
    EXPECT(tsnet_control_key_parse(REAL, sizeof REAL - 2, pub) == -1);

    if (failures == 0) {
        printf("tsnet controlkey_test: ok\n");
    }
    return failures != 0;
}
