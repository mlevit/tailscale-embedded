// JSON from the network, parsed safely. See json.h.
#include "json.h"
#include <stdbool.h>
#include "platform.h"

// The deepest nesting of arrays and objects, counted outside strings, stopping once past `max`.
static int depth(const char *s, size_t len, int max)
{
    int d = 0, deepest = 0;
    bool in_str = false;
    for (size_t i = 0; i < len && s[i] && deepest <= max; i++) {
        char c = s[i];
        if (in_str) {
            if (c == '\\') {
                i++; // the escaped character, whatever it is
            } else if (c == '"') {
                in_str = false;
            }
        } else if (c == '"') {
            in_str = true;
        } else if (c == '[' || c == '{') {
            if (++d > deepest) {
                deepest = d;
            }
        } else if ((c == ']' || c == '}') && d > 0) {
            d--;
        }
    }
    return deepest;
}

cJSON *tsnet_json_parse(const char *json, size_t len)
{
    if (!json) {
        return NULL;
    }
    if (depth(json, len, TSNET_JSON_MAX_DEPTH) > TSNET_JSON_MAX_DEPTH) {
        tsnet_log(TSNET_LOG_WARN, "json: nested deeper than %d levels: refused", TSNET_JSON_MAX_DEPTH);
        return NULL;
    }
    return cJSON_ParseWithLength(json, len);
}
