// tailcfg's wire types. See tailcfg.h.
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#elif !defined(ESP_PLATFORM)
#define _DEFAULT_SOURCE
#endif
#include "tailcfg.h"
#include <sys/socket.h> // before arpa/inet.h: ESP-IDF's lwIP declares inet_pton/ntop and AF_* through it
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "json.h"

// ---- keys ----

void tsnet_key_text(char *out, const char *prefix, const uint8_t key[TSNET_KEY_LEN])
{
    static const char HEX[] = "0123456789abcdef";
    size_t n = strlen(prefix);
    memcpy(out, prefix, n);
    for (int i = 0; i < TSNET_KEY_LEN; i++) {
        out[n + 2 * i] = HEX[key[i] >> 4];
        out[n + 2 * i + 1] = HEX[key[i] & 15];
    }
    out[n + 2 * TSNET_KEY_LEN] = '\0';
}

static int hexval(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

int tsnet_key_parse(uint8_t key[TSNET_KEY_LEN], const char *prefix, const char *text)
{
    size_t n = strlen(prefix);
    if (text == NULL || strncmp(text, prefix, n) != 0 || strlen(text) != n + 2 * TSNET_KEY_LEN) {
        return -1;
    }
    for (int i = 0; i < TSNET_KEY_LEN; i++) {
        int hi = hexval(text[n + 2 * i]), lo = hexval(text[n + 2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        key[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

// ---- addresses ----

int tsnet_ip_parse(tsnet_ip_t *ip, const char *s)
{
    memset(ip, 0, sizeof *ip);
    if (s == NULL || strchr(s, '%') != NULL) {
        return -1; // a zone isn't something control sends us
    }
    if (strchr(s, ':') == NULL) {
        return inet_pton(AF_INET, s, ip->ip) == 1 ? 0 : -1;
    }
    ip->is6 = 1;
    return inet_pton(AF_INET6, s, ip->ip) == 1 ? 0 : -1;
}

int tsnet_prefix_parse(tsnet_prefix_t *p, const char *s)
{
    char buf[64];
    const char *slash = s ? strchr(s, '/') : NULL;
    if (slash == NULL || (size_t)(slash - s) >= sizeof buf) {
        return -1;
    }
    memcpy(buf, s, (size_t)(slash - s));
    buf[slash - s] = '\0';
    char *end;
    long bits = strtol(slash + 1, &end, 10);
    if (tsnet_ip_parse(&p->ip, buf) != 0 || *end != '\0' || end == slash + 1 || bits < 0 || bits > (p->ip.is6 ? 128 : 32)) {
        return -1;
    }
    p->bits = (uint8_t)bits;
    return 0;
}

int tsnet_addrport_parse(tsnet_addrport_t *a, const char *s)
{
    char buf[64];
    const char *colon;
    if (s == NULL) {
        return -1;
    }
    if (s[0] == '[') { // [v6]:port
        const char *close = strchr(s, ']');
        if (close == NULL || close[1] != ':' || (size_t)(close - s - 1) >= sizeof buf) {
            return -1;
        }
        memcpy(buf, s + 1, (size_t)(close - s - 1));
        buf[close - s - 1] = '\0';
        colon = close + 1;
        if (strchr(buf, ':') == NULL) {
            return -1;
        }
    } else {
        colon = strrchr(s, ':');
        if (colon == NULL || (size_t)(colon - s) >= sizeof buf) {
            return -1;
        }
        memcpy(buf, s, (size_t)(colon - s));
        buf[colon - s] = '\0';
        if (strchr(buf, ':') != NULL) {
            return -1; // an IPv6 address needs its brackets
        }
    }
    char *end;
    long port = strtol(colon + 1, &end, 10);
    if (tsnet_ip_parse(&a->ip, buf) != 0 || *end != '\0' || end == colon + 1 || port < 0 || port > 65535) {
        return -1;
    }
    a->port = (uint16_t)port;
    return 0;
}

void tsnet_addrport_text(char *out, size_t cap, const tsnet_addrport_t *a)
{
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(a->ip.is6 ? AF_INET6 : AF_INET, a->ip.ip, ip, sizeof ip);
    snprintf(out, cap, a->ip.is6 ? "[%s]:%u" : "%s:%u", ip, (unsigned)a->port);
}

// ---- encoding ----

// time.Time's JSON: RFC 3339 in UTC; Go's zero time when unset.
static void time_text(char *out, size_t cap, int64_t unix)
{
    if (unix == 0) {
        snprintf(out, cap, "0001-01-01T00:00:00Z");
        return;
    }
    time_t t = (time_t)unix;
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void add_key(cJSON *o, const char *name, const char *prefix, const uint8_t *key)
{
    char text[TSNET_KEY_TEXT_MAX];
    tsnet_key_text(text, prefix, key);
    cJSON_AddStringToObject(o, name, text);
}

static void add_str_nonempty(cJSON *o, const char *name, const char *v)
{
    if (v != NULL && v[0] != '\0') { // omitzero
        cJSON_AddStringToObject(o, name, v);
    }
}

static cJSON *hostinfo(const tsnet_hostinfo_t *h)
{
    cJSON *o = cJSON_CreateObject();
    if (o == NULL || h == NULL) {
        return o;
    }
    add_str_nonempty(o, "IPNVersion", h->ipn_version);
    add_str_nonempty(o, "BackendLogID", h->backend_log_id);
    add_str_nonempty(o, "OS", h->os);
    add_str_nonempty(o, "OSVersion", h->os_version);
    add_str_nonempty(o, "Hostname", h->hostname);
    add_str_nonempty(o, "Machine", h->machine);
    const tsnet_net_info_t *n = h->net_info;
    if (n) {
        // In NetInfo's field order. The opt.Bools are written when set; omitzero leaves out the rest.
        cJSON *ni = cJSON_AddObjectToObject(o, "NetInfo");
        if (n->mapping_varies >= 0) {
            cJSON_AddBoolToObject(ni, "MappingVariesByDestIP", n->mapping_varies);
        }
        cJSON_AddBoolToObject(ni, "WorkingIPv6", 0);
        cJSON_AddBoolToObject(ni, "OSHasIPv6", 0);
        cJSON_AddBoolToObject(ni, "WorkingUDP", n->working_udp);
        cJSON_AddBoolToObject(ni, "WorkingICMPv4", 0);
        if (n->preferred_derp) {
            cJSON_AddNumberToObject(ni, "PreferredDERP", n->preferred_derp);
        }
        if (n->n_derp_latency) {
            cJSON *lat = cJSON_AddObjectToObject(ni, "DERPLatency");
            for (size_t i = 0; i < n->n_derp_latency && i < TSNET_NETINFO_LATENCIES; i++) {
                char key[16];
                snprintf(key, sizeof key, "%d-v4", n->derp_latency[i].region);
                cJSON_AddNumberToObject(lat, key, n->derp_latency[i].seconds);
            }
        }
    }
    return o;
}

static char *finish(cJSON *root)
{
    char *s = root ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    return s;
}

char *tsnet_register_request_json(const tsnet_register_req_t *r)
{
    // tailcfg.RegisterRequest, filled as doLogin does; the fields without omitempty are always written, as Go does.
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    char t[32];
    cJSON_AddNumberToObject(root, "Version", r->version);
    add_key(root, "NodeKey", TSNET_KEY_NODE, r->node_key);
    add_key(root, "OldNodeKey", TSNET_KEY_NODE, r->old_node_key);
    if (r->nl_key) {
        add_key(root, "NLKey", TSNET_KEY_NL, r->nl_key);
    }
    if (r->auth_key && r->auth_key[0]) {
        cJSON *auth = cJSON_AddObjectToObject(root, "Auth");
        // A reference, not a copy: cJSON would free its copy of the key without wiping it.
        cJSON_AddItemToObject(auth, "AuthKey", cJSON_CreateStringReference(r->auth_key));
    }
    time_text(t, sizeof t, r->expiry);
    cJSON_AddStringToObject(root, "Expiry", t);
    cJSON_AddStringToObject(root, "Followup", r->followup ? r->followup : "");
    cJSON_AddItemToObject(root, "Hostinfo", hostinfo(r->hostinfo));
    if (r->ephemeral) {
        cJSON_AddBoolToObject(root, "Ephemeral", 1);
    }
    cJSON_AddNullToObject(root, "NodeKeySignature"); // tkatype.MarshaledSignature, nil without tailnet lock
    if (r->timestamp) {
        time_text(t, sizeof t, r->timestamp);
        cJSON_AddStringToObject(root, "Timestamp", t);
    }
    return finish(root);
}

char *tsnet_map_request_json(const tsnet_map_req_t *r)
{
    // tailcfg.MapRequest, filled as sendMapRequest does.
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    cJSON_AddNumberToObject(root, "Version", r->version);
    add_str_nonempty(root, "Compress", r->compress);
    if (r->keep_alive) {
        cJSON_AddBoolToObject(root, "KeepAlive", 1);
    }
    add_key(root, "NodeKey", TSNET_KEY_NODE, r->node_key);
    add_key(root, "DiscoKey", TSNET_KEY_DISCO, r->disco_key);
    if (r->stream) {
        cJSON_AddBoolToObject(root, "Stream", 1);
    }
    cJSON_AddItemToObject(root, "Hostinfo", hostinfo(r->hostinfo));
    if (r->n_endpoints) {
        cJSON *eps = cJSON_AddArrayToObject(root, "Endpoints");
        cJSON *types = cJSON_AddArrayToObject(root, "EndpointTypes");
        for (size_t i = 0; i < r->n_endpoints; i++) {
            char text[64];
            tsnet_addrport_text(text, sizeof text, &r->endpoints[i]);
            cJSON_AddItemToArray(eps, cJSON_CreateString(text));
            cJSON_AddItemToArray(types, cJSON_CreateNumber(r->endpoint_types ? r->endpoint_types[i] : 0));
        }
    }
    if (r->omit_peers) {
        cJSON_AddBoolToObject(root, "OmitPeers", 1);
    }
    return finish(root);
}

// ---- decoding ----

static void get_str(char *out, size_t cap, const cJSON *o, const char *name)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, name);
    out[0] = '\0';
    if (cJSON_IsString(v)) {
        snprintf(out, cap, "%s", v->valuestring);
    }
}

static bool get_bool(const cJSON *o, const char *name)
{
    return cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(o, name));
}

int tsnet_register_response_parse(tsnet_register_resp_t *r, const char *json, size_t len)
{
    memset(r, 0, sizeof *r);
    cJSON *root = tsnet_json_parse(json, len);
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return -1;
    }
    get_str(r->error, sizeof r->error, root, "Error");
    get_str(r->auth_url, sizeof r->auth_url, root, "AuthURL");
    r->node_key_expired = get_bool(root, "NodeKeyExpired");
    r->machine_authorized = get_bool(root, "MachineAuthorized");
    const cJSON *sig = cJSON_GetObjectItemCaseSensitive(root, "NodeKeySignature");
    r->has_node_key_signature = cJSON_IsString(sig) && sig->valuestring[0] != '\0'; // []byte: base64, or null
    get_str(r->login_name, sizeof r->login_name, cJSON_GetObjectItemCaseSensitive(root, "Login"), "LoginName");
    cJSON_Delete(root);
    return 0;
}
