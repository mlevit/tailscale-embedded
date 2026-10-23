// Host test of tsnet's netmap session: sequences of map messages, as map.go's mapSession applies them, with the
// state checked after each; the first message is headscale's real one. Under ASan and UBSan.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netmap.h"
#include "policy.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

#define NK(last) "\"nodekey:00000000000000000000000000000000000000000000000000000000000000" last "\""

static int apply(tsnet_netmap_t *nm, const char *json, int64_t now)
{
    tsnet_map_resp_t r;
    if (tsnet_map_response_parse(&r, json, strlen(json)) != 0) {
        printf("fixture didn't parse: %s\n", json);
        failures++;
        return -100;
    }
    int f = tsnet_netmap_apply(nm, &r, now);
    tsnet_map_response_free(&r);
    return f;
}

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("can't read %s\n", path);
        failures++;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    b[fread(b, 1, (size_t)n, f)] = '\0';
    fclose(f);
    return b;
}

static size_t ids(const tsnet_netmap_t *nm, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    for (size_t i = 0; i < nm->n_peers; i++) {
        n += (size_t)snprintf(out + n, cap - n, "%s%lld", i ? "," : "", (long long)nm->peers[i].id);
    }
    return n;
}

int main(int argc, char **argv)
{
    char path[1024], list[256];
    snprintf(path, sizeof path, "%s/headscale/map-01.json", argc > 1 ? argv[1] : "test/fixtures");
    tsnet_netmap_t nm;

    // The first message must carry Node; keep-alives before it are fine.
    tsnet_netmap_init(&nm);
    EXPECT(apply(&nm, "{\"KeepAlive\":true,\"ControlTime\":\"2026-10-23T01:31:30Z\"}", 0) == 0 &&
           nm.control_time == 1792719090);
    EXPECT(apply(&nm, "{\"Peers\":[{\"ID\":5}]}", 0) == -1);
    tsnet_netmap_free(&nm);

    // headscale's real answer to a deleted node's poll: a placeholder self node whose key expired in 1970, which is
    // ipnlocal's keyExpired (the client's NEEDS_AUTH).
    {
        char del[1024];
        snprintf(del, sizeof del, "%s/headscale/map-deleted.json", argc > 1 ? argv[1] : "test/fixtures");
        tsnet_netmap_init(&nm);
        char *msg = slurp(del);
        int df = msg ? apply(&nm, msg, 0) : -1;
        free(msg);
        EXPECT(df > 0 && (df & TSNET_NM_SELF) && nm.has_node && nm.node.id == 0 && nm.node.key_expiry == 1 &&
               nm.n_peers == 0 && tsnet_self_expired(&nm.node, 1792567680));
        tsnet_netmap_free(&nm);
    }

    // headscale's real first message, then deltas.
    tsnet_netmap_init(&nm);
    char *real = slurp(path);
    int f = real ? apply(&nm, real, 0) : -1;
    free(real);
    EXPECT(f == (TSNET_NM_SELF | TSNET_NM_PEERS | TSNET_NM_DERP | TSNET_NM_FILTER | TSNET_NM_DOMAIN));
    EXPECT(nm.has_node && strcmp(nm.node.name, "tsnet-capture.tsnet.test.") == 0 && nm.n_peers == 1 &&
           nm.peers[0].id == 1 && nm.derp_map && nm.derp_map->n_regions == 28 && nm.n_filters == 1 &&
           strcmp(nm.filters[0].name, "base") == 0 && strcmp(nm.domain, "127.0.0.1") == 0);
    tsnet_ip_t ip;
    tsnet_ip_parse(&ip, "100.64.0.1");
    EXPECT(tsnet_netmap_peer_by_ip(&nm, &ip) == &nm.peers[0]);
    EXPECT(tsnet_netmap_peer_by_key(&nm, nm.peers[0].key) == &nm.peers[0]);
    // MagicDNS names: the short name or the FQDN, with or without its dot; not a prefix of either.
    EXPECT(tsnet_netmap_peer_by_name(&nm, "tsnet-peer") == &nm.peers[0]);
    EXPECT(tsnet_netmap_peer_by_name(&nm, "tsnet-peer.tsnet.test") == &nm.peers[0]);
    EXPECT(tsnet_netmap_peer_by_name(&nm, "tsnet-peer.tsnet.test.") == &nm.peers[0]);
    EXPECT(!tsnet_netmap_peer_by_name(&nm, "tsnet") && !tsnet_netmap_peer_by_name(&nm, "tsnet-peer.tsnet") &&
           !tsnet_netmap_peer_by_name(&nm, "") && !tsnet_netmap_peer_by_name(&nm, "tsnet-capture"));

    // A later message without Node is fine; PeersChanged adds, kept sorted by id.
    EXPECT(apply(&nm, "{\"PeersChanged\":[{\"ID\":9,\"Key\":" NK("09") ",\"Addresses\":[\"100.64.0.9/32\"]},"
                      "{\"ID\":3,\"Key\":" NK("03") ",\"Addresses\":[\"100.64.0.3/32\"]}]}",
                 0) == TSNET_NM_PEERS);
    ids(&nm, list, sizeof list);
    EXPECT(strcmp(list, "1,3,9") == 0);
    // PeersChanged for a known id replaces it.
    EXPECT(apply(&nm, "{\"PeersChanged\":[{\"ID\":3,\"Key\":" NK("33") ",\"Addresses\":[\"100.64.0.33/32\"]}]}", 0) ==
           TSNET_NM_PEERS);
    tsnet_ip_parse(&ip, "100.64.0.3");
    EXPECT(tsnet_netmap_peer_by_ip(&nm, &ip) == NULL);
    tsnet_ip_parse(&ip, "100.64.0.33");
    EXPECT(tsnet_netmap_peer_by_ip(&nm, &ip) && tsnet_netmap_peer_by_ip(&nm, &ip)->key[31] == 0x33);

    // Removed, then the order within one message: PeersRemoved before PeersChanged (a peer re-added in the same message
    // stays), then seen, online, then patches.
    EXPECT(apply(&nm, "{\"PeersRemoved\":[9,77],\"PeersChanged\":[{\"ID\":9,\"Key\":" NK("99") "}],"
                      "\"PeerSeenChange\":{\"3\":true,\"77\":true},\"OnlineChange\":{\"3\":true},"
                      "\"PeersChangedPatch\":[{\"NodeID\":3,\"Online\":false,\"DERPRegion\":7,\"Endpoints\":"
                      "[\"192.0.2.1:41641\"],\"Cap\":120,\"KeyExpiry\":\"2027-01-01T00:00:00Z\",\"DiscoKey\":"
                      "\"discokey:00000000000000000000000000000000000000000000000000000000000000dd\"},"
                      "{\"NodeID\":404,\"DERPRegion\":1}]}",
                 1792719090) == TSNET_NM_PEERS);
    ids(&nm, list, sizeof list);
    EXPECT(strcmp(list, "1,3,9") == 0);
    const tsnet_node_t *p3 = tsnet_netmap_peer(&nm, 3);
    EXPECT(p3 && p3->last_seen == 1792719090 && p3->online == 0 && p3->home_derp == 7 && p3->n_endpoints == 1 &&
           p3->endpoints[0].port == 41641 && p3->cap == 120 && p3->key_expiry > 0 && p3->has_disco &&
           p3->disco[31] == 0xdd);
    EXPECT(tsnet_netmap_peer(&nm, 9) && tsnet_netmap_peer(&nm, 9)->key[31] == 0x99);
    // Not seen clears LastSeen; an unknown id in a map is ignored.
    EXPECT(apply(&nm, "{\"PeerSeenChange\":{\"3\":false},\"OnlineChange\":{\"404\":true}}", 5) == TSNET_NM_PEERS);
    EXPECT(tsnet_netmap_peer(&nm, 3)->last_seen == 0 && tsnet_netmap_peer(&nm, 3)->online == 0);
    // Patch Endpoints to [] empties them; an absent field leaves its value.
    EXPECT(apply(&nm, "{\"PeersChangedPatch\":[{\"NodeID\":3,\"Endpoints\":[]}]}", 0) == TSNET_NM_PEERS);
    EXPECT(tsnet_netmap_peer(&nm, 3)->n_endpoints == 0 && tsnet_netmap_peer(&nm, 3)->home_derp == 7);
    // Nothing that touches a known peer: no flags.
    EXPECT(apply(&nm, "{\"PeersRemoved\":[12345]}", 0) == 0);

    // A full Peers list replaces everything, and nothing else in that message applies to peers.
    EXPECT(apply(&nm, "{\"Peers\":[{\"ID\":20,\"Key\":" NK("20") "},{\"ID\":2,\"Key\":" NK("02") "}],"
                      "\"PeersRemoved\":[20],\"OnlineChange\":{\"2\":true}}",
                 0) == TSNET_NM_PEERS);
    ids(&nm, list, sizeof list);
    EXPECT(strcmp(list, "2,20") == 0 && tsnet_netmap_peer(&nm, 2)->online == -1);

    // The DERP map merge: absent Regions keep the old ones; HomeParams absent keeps the old; present without RegionScore
    // keeps the old RegionScore.
    EXPECT(apply(&nm, "{\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":0.5}}}}", 0) == TSNET_NM_DERP);
    EXPECT(nm.derp_map->n_regions == 28 && nm.derp_map->has_region_score && nm.derp_map->region_score[0].score == 0.5);
    EXPECT(apply(&nm, "{\"DERPMap\":{\"Regions\":{\"900\":{\"RegionID\":900,\"RegionCode\":\"x\",\"Nodes\":[]}}}}", 0) ==
           TSNET_NM_DERP);
    EXPECT(nm.derp_map->n_regions == 1 && nm.derp_map->regions[0].region_id == 900 && nm.derp_map->has_region_score);
    EXPECT(apply(&nm, "{\"DERPMap\":{\"HomeParams\":{}}}", 0) == TSNET_NM_DERP);
    EXPECT(nm.derp_map->n_regions == 1 && nm.derp_map->has_home_params && nm.derp_map->has_region_score &&
           nm.derp_map->n_region_score == 1);
    EXPECT(apply(&nm, "{\"DERPMap\":{\"Regions\":{},\"HomeParams\":{\"RegionScore\":{}}}}", 0) == TSNET_NM_DERP);
    EXPECT(nm.derp_map->has_regions && nm.derp_map->n_regions == 0 && nm.derp_map->n_region_score == 0);

    // Named packet filters: set, add, delete by null, [] kept as an empty list, "*": null clears; the rules come out
    // concatenated in name order.
    EXPECT(apply(&nm, "{\"PacketFilters\":{\"zz\":[{\"SrcIPs\":[\"z\"]}],\"aa\":[{\"SrcIPs\":[\"a\"]}]}}", 0) ==
           TSNET_NM_FILTER);
    char *rules = tsnet_netmap_filter_rules_json(&nm);
    EXPECT(nm.n_filters == 3 && rules && strstr(rules, "\"a\"") < strstr(rules, "\"z\"") && strstr(rules, "\"a\"") &&
           strstr(rules, "\"z\""));
    free(rules);
    EXPECT(apply(&nm, "{\"PacketFilters\":{\"zz\":null,\"aa\":[]}}", 0) == TSNET_NM_FILTER);
    EXPECT(nm.n_filters == 2 && strcmp(nm.filters[0].name, "aa") == 0 && strcmp(nm.filters[0].rules_json, "[]") == 0);
    EXPECT(apply(&nm, "{\"PacketFilters\":{\"*\":null,\"new\":[{\"SrcIPs\":[\"n\"]}]}}", 0) == TSNET_NM_FILTER);
    EXPECT(nm.n_filters == 1 && strcmp(nm.filters[0].name, "new") == 0);
    EXPECT(apply(&nm, "{\"PacketFilter\":[{\"SrcIPs\":[\"b\"]}]}", 0) == TSNET_NM_FILTER);
    EXPECT(nm.n_filters == 2 && strcmp(nm.filters[0].name, "base") == 0);
    EXPECT(apply(&nm, "{\"PacketFilters\":{\"*\":null}}", 0) == TSNET_NM_FILTER && nm.n_filters == 0 &&
           tsnet_netmap_filter_rules_json(&nm) == NULL);

    // The self node replaced; the domain only when it changes; a keep-alive changes nothing.
    EXPECT(apply(&nm, "{\"Node\":{\"ID\":2,\"Name\":\"renamed.tsnet.test.\",\"Key\":" NK("aa") "}}", 0) == TSNET_NM_SELF);
    EXPECT(strcmp(nm.node.name, "renamed.tsnet.test.") == 0);
    EXPECT(apply(&nm, "{\"Domain\":\"127.0.0.1\"}", 0) == 0);
    EXPECT(apply(&nm, "{\"Domain\":\"example.test\"}", 0) == TSNET_NM_DOMAIN);
    EXPECT(apply(&nm, "{\"KeepAlive\":true,\"PeersRemoved\":[2]}", 0) == 0 && tsnet_netmap_peer(&nm, 2));
    tsnet_netmap_free(&nm);

    // Many peers in and out, in random order: the list stays sorted and complete.
    tsnet_netmap_init(&nm);
    EXPECT(apply(&nm, "{\"Node\":{\"ID\":1}}", 0) == TSNET_NM_SELF);
    uint32_t seed = 9;
    int present[200] = {0};
    for (int i = 0; i < 2000; i++) {
        seed = seed * 1103515245 + 12345;
        int id = (int)((seed >> 16) % 200);
        char msg[160];
        if (seed & 0x10000000) {
            snprintf(msg, sizeof msg, "{\"PeersChanged\":[{\"ID\":%d}]}", id);
            present[id] = 1;
        } else {
            snprintf(msg, sizeof msg, "{\"PeersRemoved\":[%d]}", id);
            present[id] = 0;
        }
        apply(&nm, msg, 0);
    }
    size_t want = 0;
    for (int i = 0; i < 200; i++) {
        want += (size_t)present[i];
        EXPECT((tsnet_netmap_peer(&nm, i) != NULL) == (present[i] == 1));
    }
    EXPECT(nm.n_peers == want);
    for (size_t i = 1; i < nm.n_peers; i++) {
        EXPECT(nm.peers[i - 1].id < nm.peers[i].id);
    }
    tsnet_netmap_free(&nm);

    if (failures == 0) {
        printf("tsnet netmap_test: ok\n");
    }
    return failures != 0;
}
