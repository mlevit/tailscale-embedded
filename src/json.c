// JSON from the network, parsed safely. See json.h.
#include "json.h"
#include <stdbool.h>
#include "platform.h"

// The deepest nesting of arrays and objects, counted outside strings, stopping once past `max`. `*values` gets the
// count of openers and commas outside strings (the values the tree will hold, within a few), and the scan stops once
// it is past `max_values`.
static int depth(const char *s, size_t len, int max, size_t max_values, size_t *values)
{
    int d = 0, deepest = 0;
    bool in_str = false;
    *values = 0;
    for (size_t i = 0; i < len && s[i] && deepest <= max && *values <= max_values; i++) {
        char c = s[i];
        if (in_str) {
            if (c == '\\') {
                i++; // the escaped character, whatever it is
            } else if (c == '"') {
                in_str = false;
            }
        } else if (c == '"') {
            in_str = true;
        } else if (c == ',') {
            (*values)++;
        } else if (c == '[' || c == '{') {
            (*values)++;
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
    size_t values;
    if (depth(json, len, TSNET_JSON_MAX_DEPTH, TSNET_JSON_MAX_VALUES, &values) > TSNET_JSON_MAX_DEPTH) {
        tsnet_log(TSNET_LOG_WARN, "json: nested deeper than TSNET_JSON_MAX_DEPTH (%d levels): refused", TSNET_JSON_MAX_DEPTH);
        return NULL;
    }
    if (values > TSNET_JSON_MAX_VALUES) {
        tsnet_log(TSNET_LOG_WARN, "json: more than TSNET_JSON_MAX_VALUES (%d) values: refused", TSNET_JSON_MAX_VALUES);
        return NULL;
    }
    return cJSON_ParseWithLength(json, len);
}
