// Host test of tsnet's tailcfg wire types: keys, addresses and times; the requests the client sends, read back;
// headscale's real responses (test/fixtures/headscale, captured by capture.c, this network's addresses scrubbed); and
// hand-built responses for the fields headscale didn't send, under ASan and UBSan.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "mapresp.h"
#include "tailcfg.h"

static int failures;
#define EXPECT(cond)                                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("%s:%d: expected %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                    \
        }                                                                  \
    } while (0)

static char *slurp(const char *dir, const char *name, size_t *len)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("can't read %s\n", path);
        failures++;
        *len = 0;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    *len = fread(buf, 1, (size_t)n, f);
    buf[*len] = '\0';
    fclose(f);
    return buf;
}

static int parse(tsnet_map_resp_t *m, const char *json)
{
    return tsnet_map_response_parse(m, json, strlen(json));
}

int main(int argc, char **argv)
{
    char fixtures[1024];
    snprintf(fixtures, sizeof fixtures, "%s/headscale", argc > 1 ? argv[1] : "test/fixtures");

    // Keys.
    {
        uint8_t k[32], k2[32];
        for (int i = 0; i < 32; i++) {
            k[i] = (uint8_t)(i * 9);
        }
        char text[TSNET_KEY_TEXT_MAX];
        tsnet_key_text(text, TSNET_KEY_NODE, k);
        EXPECT(strcmp(text, "nodekey:0009121b242d363f48515a636c757e879099a2abb4bdc6cfd8e1eaf3fc050e17") == 0);
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_NODE, text) == 0 && memcmp(k, k2, 32) == 0);
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_NODE, "nodekey:0009121B242D363F48515A636C757E879099A2ABB4BDC6CFD8E1EAF3FC050E17") == 0 &&
               memcmp(k, k2, 32) == 0);
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_DISCO, text) == -1);                // wrong prefix
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_NODE, "nodekey:0009") == -1);       // short
        text[20] = 'g';
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_NODE, text) == -1);                 // not hex
        EXPECT(tsnet_key_parse(k2, TSNET_KEY_NODE, NULL) == -1);
    }

    // Addresses.
    {
        tsnet_prefix_t p;
        tsnet_addrport_t a;
        tsnet_ip_t ip;
        EXPECT(tsnet_prefix_parse(&p, "100.64.0.2/32") == 0 && !p.ip.is6 && p.bits == 32 && p.ip.ip[0] == 100 && p.ip.ip[3] == 2);
        EXPECT(tsnet_prefix_parse(&p, "fd7a:115c:a1e0::2/128") == 0 && p.ip.is6 && p.bits == 128 && p.ip.ip[0] == 0xfd &&
               p.ip.ip[15] == 2);
        EXPECT(tsnet_prefix_parse(&p, "0.0.0.0/0") == 0 && p.bits == 0);
        EXPECT(tsnet_prefix_parse(&p, "10.0.0.0/33") == -1 && tsnet_prefix_parse(&p, "::/129") == -1);
        EXPECT(tsnet_prefix_parse(&p, "10.0.0.0") == -1 && tsnet_prefix_parse(&p, "10.0.0.0/") == -1 &&
               tsnet_prefix_parse(&p, "10.0.0/8") == -1 && tsnet_prefix_parse(&p, "10.0.0.0/8x") == -1);
        EXPECT(tsnet_addrport_parse(&a, "203.0.113.7:62290") == 0 && !a.ip.is6 && a.port == 62290);
        EXPECT(tsnet_addrport_parse(&a, "[2001:db8::1]:41641") == 0 && a.ip.is6 && a.port == 41641);
        EXPECT(tsnet_addrport_parse(&a, "2001:db8::1:41641") == -1); // IPv6 needs brackets
        EXPECT(tsnet_addrport_parse(&a, "1.2.3.4:65536") == -1 && tsnet_addrport_parse(&a, "1.2.3.4") == -1 &&
               tsnet_addrport_parse(&a, "[1.2.3.4]:1") == -1 && tsnet_addrport_parse(&a, "1.2.3.4:") == -1);
        EXPECT(tsnet_ip_parse(&ip, "fe80::1%eth0") == -1);
        char text[64];
        tsnet_addrport_parse(&a, "[2001:db8::1]:41641");
        tsnet_addrport_text(text, sizeof text, &a);
        EXPECT(strcmp(text, "[2001:db8::1]:41641") == 0);
        tsnet_addrport_parse(&a, "192.0.2.3:41641");
        tsnet_addrport_text(text, sizeof text, &a);
        EXPECT(strcmp(text, "192.0.2.3:41641") == 0);
    }

    // Times (the expected values from Python's datetime).
    {
        int64_t t;
        EXPECT(tsnet_time_parse(&t, "2026-10-23T01:31:30.331172539Z") == 0 && t == 1792719090);
        EXPECT(tsnet_time_parse(&t, "2026-10-23T03:31:30+02:00") == 0 && t == 1792719090);
        EXPECT(tsnet_time_parse(&t, "2026-10-22T23:31:30-02:00") == 0 && t == 1792719090);
        EXPECT(tsnet_time_parse(&t, "1999-12-31T23:59:59Z") == 0 && t == 946684799);
        EXPECT(tsnet_time_parse(&t, "2024-02-29T12:00:00Z") == 0 && t == 1709208000);
        EXPECT(tsnet_time_parse(&t, "0001-01-01T00:00:00Z") == 0 && t == 0);
        static const char *BAD[] = {"", "2026-10-23", "2026-10-23T01:31:30", "2026-10-23T01:31:30.Z", "2026-13-01T00:00:00Z",
                                    "2026-10-23T01:31:30Zjunk", "2026-10-23 01:31:30Z", "2026-10-23T01:31:30+0200"};
        for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
            EXPECT(tsnet_time_parse(&t, BAD[i]) == -1);
        }
    }

    // The requests, read back as JSON.
    {
        tsnet_net_info_t ni = {.preferred_derp = 12, .working_udp = true, .mapping_varies = -1,
                               .derp_latency = {{12, 0.0125}, {1, 0.25}}, .n_derp_latency = 2};
        tsnet_hostinfo_t hi = {"tsnet-0.1", "abcd", "linux", "ESP-IDF 5.5", "tsnet-node", "esp32p4", &ni};
        tsnet_register_req_t r = {.version = 131, .auth_key = "tskey-auth-x", .timestamp = 1792719090, .hostinfo = &hi};
        memset(r.node_key, 0x11, 32);
        char *s = tsnet_register_request_json(&r);
        cJSON *j = cJSON_Parse(s);
        EXPECT(j && cJSON_GetObjectItem(j, "Version")->valueint == 131);
        EXPECT(strncmp(cJSON_GetObjectItem(j, "NodeKey")->valuestring, "nodekey:1111", 12) == 0);
        EXPECT(strcmp(cJSON_GetObjectItem(j, "OldNodeKey")->valuestring,
                      "nodekey:0000000000000000000000000000000000000000000000000000000000000000") == 0);
        EXPECT(cJSON_GetObjectItem(j, "NLKey") == NULL); // left out unless given
        EXPECT(strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(j, "Auth"), "AuthKey")->valuestring, "tskey-auth-x") == 0);
        EXPECT(strcmp(cJSON_GetObjectItem(j, "Expiry")->valuestring, "0001-01-01T00:00:00Z") == 0);
        EXPECT(strcmp(cJSON_GetObjectItem(j, "Timestamp")->valuestring, "2026-10-23T01:31:30Z") == 0);
        EXPECT(cJSON_IsNull(cJSON_GetObjectItem(j, "NodeKeySignature")));
        EXPECT(cJSON_GetObjectItem(j, "Ephemeral") == NULL);
        cJSON *h = cJSON_GetObjectItem(j, "Hostinfo");
        EXPECT(strcmp(cJSON_GetObjectItem(h, "BackendLogID")->valuestring, "abcd") == 0 &&
               strcmp(cJSON_GetObjectItem(h, "Hostname")->valuestring, "tsnet-node") == 0 &&
               cJSON_GetObjectItem(cJSON_GetObjectItem(h, "NetInfo"), "PreferredDERP")->valueint == 12);
        // NetInfo as updateNetInfo fills it: the opt.Bools it sets, an unknown mapping left out, the latencies keyed
        // "<region>-v4" in seconds.
        cJSON *n = cJSON_GetObjectItem(h, "NetInfo");
        EXPECT(cJSON_GetObjectItem(n, "MappingVariesByDestIP") == NULL);
        EXPECT(cJSON_IsTrue(cJSON_GetObjectItem(n, "WorkingUDP")) && cJSON_IsFalse(cJSON_GetObjectItem(n, "WorkingIPv6")) &&
               cJSON_IsFalse(cJSON_GetObjectItem(n, "OSHasIPv6")) &&
               cJSON_IsFalse(cJSON_GetObjectItem(n, "WorkingICMPv4")));
        cJSON *lat = cJSON_GetObjectItem(n, "DERPLatency");
        EXPECT(cJSON_GetArraySize(lat) == 2 && cJSON_GetObjectItem(lat, "12-v4")->valuedouble == 0.0125 &&
               cJSON_GetObjectItem(lat, "1-v4")->valuedouble == 0.25);
        EXPECT(cJSON_GetObjectItem(n, "HavePortMap") == NULL && cJSON_GetObjectItem(n, "LinkType") == NULL);
        cJSON_Delete(j);
        free(s);
        // A known mapping is written; no NetInfo at all leaves the key out.
        ni.mapping_varies = 1;
        s = tsnet_register_request_json(&r);
        j = cJSON_Parse(s);
        EXPECT(cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(j, "Hostinfo"), "NetInfo"),
                                                "MappingVariesByDestIP")));
        cJSON_Delete(j);
        free(s);
        hi.net_info = NULL;
        s = tsnet_register_request_json(&r);
        j = cJSON_Parse(s);
        EXPECT(cJSON_GetObjectItem(cJSON_GetObjectItem(j, "Hostinfo"), "NetInfo") == NULL);
        cJSON_Delete(j);
        free(s);
        hi.net_info = &ni;
        uint8_t nl[32];
        memset(nl, 0xee, 32);
        r.nl_key = nl;
        r.timestamp = 0;
        r.auth_key = NULL;
        r.ephemeral = true;
        r.expiry = 123; // logout
        s = tsnet_register_request_json(&r);
        j = cJSON_Parse(s);
        EXPECT(strncmp(cJSON_GetObjectItem(j, "NLKey")->valuestring, "nlpub:eeee", 10) == 0);
        EXPECT(cJSON_GetObjectItem(j, "Auth") == NULL && cJSON_GetObjectItem(j, "Timestamp") == NULL);
        EXPECT(cJSON_IsTrue(cJSON_GetObjectItem(j, "Ephemeral")));
        EXPECT(strcmp(cJSON_GetObjectItem(j, "Expiry")->valuestring, "1970-01-01T00:02:03Z") == 0);
        cJSON_Delete(j);
        free(s);

        tsnet_addrport_t eps[2];
        tsnet_addrport_parse(&eps[0], "203.0.113.7:41641");
        tsnet_addrport_parse(&eps[1], "[2001:db8::1]:41641");
        int types[2] = {3, 1};
        tsnet_map_req_t m = {.version = 131, .compress = "zstd", .keep_alive = true, .stream = true, .endpoints = eps,
                             .endpoint_types = types, .n_endpoints = 2, .hostinfo = &hi};
        memset(m.node_key, 0x22, 32);
        memset(m.disco_key, 0x33, 32);
        s = tsnet_map_request_json(&m);
        j = cJSON_Parse(s);
        EXPECT(strcmp(cJSON_GetObjectItem(j, "Compress")->valuestring, "zstd") == 0);
        EXPECT(cJSON_IsTrue(cJSON_GetObjectItem(j, "KeepAlive")) && cJSON_IsTrue(cJSON_GetObjectItem(j, "Stream")));
        EXPECT(cJSON_GetObjectItem(j, "OmitPeers") == NULL);
        EXPECT(strncmp(cJSON_GetObjectItem(j, "DiscoKey")->valuestring, "discokey:3333", 13) == 0);
        cJSON *e = cJSON_GetObjectItem(j, "Endpoints");
        EXPECT(cJSON_GetArraySize(e) == 2 && strcmp(cJSON_GetArrayItem(e, 1)->valuestring, "[2001:db8::1]:41641") == 0);
        EXPECT(cJSON_GetArrayItem(cJSON_GetObjectItem(j, "EndpointTypes"), 0)->valueint == 3);
        cJSON_Delete(j);
        free(s);
    }

    // headscale's real register response and first two map messages.
    {
        size_t len;
        char *s = slurp(fixtures, "register.json", &len);
        tsnet_register_resp_t rr;
        EXPECT(s && tsnet_register_response_parse(&rr, s, len) == 0);
        EXPECT(rr.machine_authorized && !rr.node_key_expired && rr.error[0] == 0 && rr.auth_url[0] == 0 &&
               !rr.has_node_key_signature && strcmp(rr.login_name, "tsnet") == 0);
        free(s);

        tsnet_map_resp_t m;
        s = slurp(fixtures, "map-01.json", &len);
        EXPECT(s && tsnet_map_response_parse(&m, s, len) == 0);
        EXPECT(!m.keep_alive && m.node && m.node->id == 2 && strcmp(m.node->name, "tsnet-capture.tsnet.test.") == 0);
        EXPECT(m.node && m.node->n_addresses == 2 && m.node->addresses[0].ip.ip[3] == 2 && m.node->addresses[1].ip.is6);
        EXPECT(m.node && m.node->n_allowed_ips == 2 && m.node->online == 1 && m.node->has_disco && m.node->cap_map_json);
        EXPECT(m.n_peers == 1 && strcmp(m.peers[0].name, "tsnet-peer.tsnet.test.") == 0 && m.peers[0].home_derp == 1);
        EXPECT(m.n_peers == 1 && m.peers[0].n_endpoints == 2 && m.peers[0].endpoints[0].port == 62290 &&
               m.peers[0].endpoints[0].ip.ip[0] == 203);
        EXPECT(m.n_peers == 1 && m.peers[0].online == 0 && m.peers[0].last_seen == 1792719090 - 692 &&
               m.peers[0].key_expiry == 0 && strcmp(m.peers[0].hostname, "tsnet-peer") == 0 && m.peers[0].key[0] == 0x7c);
        EXPECT(m.n_peers == 1 && m.peers[0].cap_map_json == NULL); // kept for the self node only
        EXPECT(m.derp_map && m.derp_map->has_regions && m.derp_map->n_regions == 28 && !m.derp_map->has_home_params);
        int found = 0;
        for (size_t i = 0; m.derp_map && i < m.derp_map->n_regions; i++) {
            if (m.derp_map->regions[i].region_id == 1) {
                found = strcmp(m.derp_map->regions[i].code, "nyc") == 0 && m.derp_map->regions[i].n_nodes == 4 &&
                        strcmp(m.derp_map->regions[i].nodes[0].host_name, "derp1f.tailscale.com") == 0 &&
                        m.derp_map->regions[i].nodes[0].can_port80;
            }
        }
        EXPECT(found);
        EXPECT(m.packet_filters_json && strstr(m.packet_filters_json, "\"base\"") && m.packet_filter_json == NULL);
        EXPECT(m.control_time == 1792719090 && strcmp(m.domain, "127.0.0.1") == 0);
        tsnet_map_response_free(&m);
        free(s);
        s = slurp(fixtures, "map-02.json", &len);
        EXPECT(s && tsnet_map_response_parse(&m, s, len) == 0 && m.node == NULL && m.n_peers == 0 && m.control_time > 0);
        tsnet_map_response_free(&m);
        free(s);
    }

    // What headscale didn't send: deltas, patches, the legacy DERP field, AllowedIPs rules, DERP map merges, a ping.
    {
        tsnet_map_resp_t m;
        EXPECT(parse(&m, "{\"KeepAlive\":true}") == 0 && m.keep_alive);
        tsnet_map_response_free(&m);
        EXPECT(parse(&m,
                     "{\"PeersChanged\":[{\"ID\":7,\"Key\":\"nodekey:"
                     "0000000000000000000000000000000000000000000000000000000000000001\",\"Addresses\":[\"100.64.0.7/32\"],"
                     "\"DERP\":\"127.3.3.40:9\",\"AllowedIPs\":[]},"
                     "{\"ID\":8,\"Addresses\":[\"100.64.0.8/32\"],\"AllowedIPs\":[\"0.0.0.0/0\",\"100.64.0.8/32\"],"
                     "\"UnsignedPeerAPIOnly\":true,\"HomeDERP\":2,\"DERP\":\"127.3.3.40:9\"}],"
                     "\"PeersRemoved\":[3,4],"
                     "\"PeersChangedPatch\":[{\"NodeID\":7,\"DERPRegion\":5,\"Endpoints\":[\"192.0.2.1:1\"],\"Online\":false,"
                     "\"LastSeen\":\"2026-10-23T01:31:30Z\",\"DiscoKey\":\"discokey:"
                     "00000000000000000000000000000000000000000000000000000000000000ff\"},{\"NodeID\":9,\"Cap\":0}],"
                     "\"OnlineChange\":{\"7\":true,\"8\":false},\"PeerSeenChange\":{\"7\":false},"
                     "\"PingRequest\":{\"URL\":\"https://example.test/p\",\"Types\":\"disco\",\"URLIsNoise\":true},"
                     "\"PacketFilter\":[{\"SrcIPs\":[\"*\"]}],\"ControlDialPlan\":{\"Candidates\":[]}}") == 0);
        EXPECT(m.n_peers_changed == 2 && m.peers_changed[0].home_derp == 9); // the legacy field, HomeDERP unset
        EXPECT(m.n_peers_changed == 2 && m.peers_changed[0].n_allowed_ips == 0); // [] isn't nil: stays empty
        EXPECT(m.n_peers_changed == 2 && m.peers_changed[1].home_derp == 2); // HomeDERP wins over the legacy field
        EXPECT(m.n_peers_changed == 2 && m.peers_changed[1].n_allowed_ips == 1 && m.peers_changed[1].allowed_ips[0].bits == 32);
        EXPECT(m.n_peers_removed == 2 && m.peers_removed[1] == 4);
        EXPECT(m.n_patches == 2 && m.patches[0].have == (TSNET_PC_DERP | TSNET_PC_ENDPOINTS | TSNET_PC_ONLINE | TSNET_PC_LAST_SEEN |
                                                        TSNET_PC_DISCO));
        EXPECT(m.n_patches == 2 && m.patches[0].derp_region == 5 && !m.patches[0].online && m.patches[0].disco[31] == 0xff &&
               m.patches[0].n_endpoints == 1 && m.patches[0].last_seen == 1792719090);
        EXPECT(m.n_patches == 2 && m.patches[1].have == 0); // a zero Cap is no change
        EXPECT(m.n_online_change == 2 && m.n_seen_change == 1 && !m.seen_change[0].value);
        int seven = 0;
        for (size_t i = 0; i < m.n_online_change; i++) {
            seven |= m.online_change[i].id == 7 && m.online_change[i].value;
        }
        EXPECT(seven);
        EXPECT(m.has_ping && strcmp(m.ping_types, "disco") == 0 && m.ping_url_is_noise && !m.ping_log);
        EXPECT(m.packet_filter_json && m.packet_filters_json == NULL && m.dial_plan_json);
        tsnet_map_response_free(&m);

        EXPECT(parse(&m, "{\"DERPMap\":{\"Regions\":{\"1\":null,\"2\":{\"RegionID\":2,\"RegionCode\":\"sfo\",\"Nodes\":[]}},"
                         "\"HomeParams\":{\"RegionScore\":{\"2\":0.5}}}}") == 0);
        EXPECT(m.derp_map && m.derp_map->n_regions == 1 && m.derp_map->regions[0].region_id == 2); // the nil region dropped
        EXPECT(m.derp_map && m.derp_map->has_region_score && m.derp_map->n_region_score == 1 &&
               m.derp_map->region_score[0].score == 0.5);
        tsnet_map_response_free(&m);
        EXPECT(parse(&m, "{\"DERPMap\":{\"HomeParams\":{}}}") == 0 && m.derp_map && !m.derp_map->has_regions &&
               m.derp_map->has_home_params && !m.derp_map->has_region_score);
        tsnet_map_response_free(&m);
    }

    // Wrong forms are errors, as json.Unmarshal's would be, and leave nothing to free.
    {
        static const char *BAD[] = {
            "", "[]", "{\"Node\":{\"Key\":\"nodekey:12\"}}", "{\"Node\":{\"Addresses\":[\"100.64.0.1\"]}}",
            "{\"Peers\":[{\"Endpoints\":[\"1.2.3.4\"]}]}", "{\"Peers\":{}}", "{\"PeersRemoved\":[\"3\"]}",
            "{\"OnlineChange\":{\"x\":true}}", "{\"OnlineChange\":{\"1\":1}}", "{\"ControlTime\":\"yesterday\"}",
            "{\"DERPMap\":{\"Regions\":[]}}", "{\"DERPMap\":{\"Regions\":{\"a\":{}}}}", "{\"KeepAlive\":\"yes\"}",
            "{\"PeersChangedPatch\":[{\"NodeID\":1,\"Key\":\"discokey:00\"}]}", "{\"Node\":{\"ID\":\"1\"}}",
            "{\"PingRequest\":[]}", "{\"Peers\":[1]}",
        };
        for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
            tsnet_map_resp_t m;
            if (parse(&m, BAD[i]) != -1) {
                printf("accepted: %s\n", BAD[i]);
                failures++;
                tsnet_map_response_free(&m);
            }
        }
        tsnet_register_resp_t rr;
        EXPECT(tsnet_register_response_parse(&rr, "null", 4) == -1 && tsnet_register_response_parse(&rr, "{", 1) == -1);
    }

    // The real map message cut at every length, and with each byte changed: a clean error or a parse, never a memory error.
    {
        size_t len;
        char *s = slurp(fixtures, "map-01.json", &len);
        for (size_t cut = 0; s && cut < len; cut += 37) {
            tsnet_map_resp_t m;
            if (tsnet_map_response_parse(&m, s, cut) == 0) {
                tsnet_map_response_free(&m);
            }
        }
        for (size_t i = 0; s && i < len; i += 11) {
            char saved = s[i];
            s[i] = (char)(saved ^ 0x21);
            tsnet_map_resp_t m;
            if (tsnet_map_response_parse(&m, s, len) == 0) {
                tsnet_map_response_free(&m);
            }
            s[i] = saved;
        }
        free(s);
    }

    if (failures == 0) {
        printf("tsnet tailcfg_test: ok\n");
    }
    return failures != 0;
}
