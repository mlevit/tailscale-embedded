// Host test of the JSON depth check (json.h) and of the control parsers it protects: JSON nested past
// TSNET_JSON_MAX_DEPTH is refused before cJSON recurses into it (on the device each level costs 96 B of stack to parse
// and 192 B to print), brackets inside strings don't count, and the map parser refuses the shapes the security review
// found: PacketFilters as an array, a DERP region under another region's ID or one ID twice, a number past int64.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json.h"
#include "mapresp.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static char *nested(int depth, char open, char close)
{
    char *s = malloc((size_t)depth * 2 + 1);
    memset(s, open, (size_t)depth);
    memset(s + depth, close, (size_t)depth);
    s[depth * 2] = '\0';
    return s;
}

static bool parses(const char *s)
{
    cJSON *j = tsnet_json_parse(s, strlen(s));
    cJSON_Delete(j);
    return j != NULL;
}

static int map_parse(const char *json)
{
    tsnet_map_resp_t r;
    int ret = tsnet_map_response_parse(&r, json, strlen(json));
    tsnet_map_response_free(&r);
    return ret;
}

int main(void)
{
    char *ok = nested(TSNET_JSON_MAX_DEPTH, '[', ']');
    char *deep = nested(TSNET_JSON_MAX_DEPTH + 1, '[', ']');
    char *bomb = nested(1000, '[', ']'); // cJSON's own limit: ~96 KB of stack on the device
    EXPECT(parses(ok) && !parses(deep) && !parses(bomb));
    bomb[1000] = '\0'; // unclosed: cJSON would still recurse 1000 levels before failing
    EXPECT(!parses(bomb));
    char *objs = malloc(2000);
    strcpy(objs, "");
    for (int i = 0; i <= TSNET_JSON_MAX_DEPTH; i++) {
        strcat(objs, "{\"a\":");
    }
    EXPECT(!parses(objs)); // objects count as arrays do
    // Brackets in strings, escaped quotes included, don't count.
    EXPECT(parses("{\"a\":\"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\\\"[[[[[[[[[[[[[\"}"));
    EXPECT(tsnet_json_parse(NULL, 0) == NULL);

    // A value count past TSNET_JSON_MAX_VALUES is refused, at the cap it parses: `[1,1,1,...` is the cheapest
    // way to make cJSON allocate.
    {
        size_t n = TSNET_JSON_MAX_VALUES + 10;
        char *flat = malloc(n * 2 + 3);
        char *p = flat;
        *p++ = '[';
        for (size_t i = 0; i < n; i++) {
            *p++ = '1', *p++ = ',';
        }
        p[-1] = ']', *p = '\0';
        EXPECT(!parses(flat));
        flat[(TSNET_JSON_MAX_VALUES - 2) * 2 + 2] = ']'; // the opener and TSNET_JSON_MAX_VALUES - 2 commas
        flat[(TSNET_JSON_MAX_VALUES - 2) * 2 + 3] = '\0';
        EXPECT(parses(flat));
        free(flat);
    }

    // The map parser goes through it too: a map message nested 1000 deep is refused, not parsed.
    char *msg = malloc(3000), *inner = nested(1000, '[', ']');
    snprintf(msg, 3000, "{\"Domain\":%s}", inner);
    free(inner);
    EXPECT(map_parse(msg) != 0);
    // PacketFilters is a map of named lists: an array (whose members have no names) fails the message.
    EXPECT(map_parse("{\"PacketFilters\":[1]}") != 0 && map_parse("{\"PacketFilter\":{}}") != 0);
    EXPECT(map_parse("{\"PacketFilters\":{\"base\":[]}}") == 0);
    // A DERP region whose RegionID isn't its key, or two regions with one ID, fail it.
    EXPECT(map_parse("{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":2}}}}") != 0);
    EXPECT(map_parse("{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1},\"1\":{\"RegionID\":1}}}}") != 0);
    EXPECT(map_parse("{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1},\"2\":{\"RegionID\":2}}}}") == 0);
    // A number past int64 (1e400 parses as inf) fails it rather than meeting an undefined cast.
    EXPECT(map_parse("{\"PeersRemoved\":[1e400]}") != 0 && map_parse("{\"PeersRemoved\":[3]}") == 0);
    free(ok), free(deep), free(bomb), free(objs), free(msg);
    if (failures == 0) {
        printf("tsnet json_test: ok\n");
    }
    return failures != 0;
}
