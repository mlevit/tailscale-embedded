#pragma once
// JSON from the network, parsed safely (the security review before open-sourcing). cJSON parses and prints by
// recursion: on the device each nesting level costs 96 B of stack to parse and 192 B to print (measured on ESP-IDF's
// cJSON), and its own limit is 1000 levels, past the 24 KB stack tsnet's task has. So everything tsnet parses goes
// through this, which refuses JSON nested deeper than TSNET_JSON_MAX_DEPTH before cJSON sees it. Tailscale's messages
// nest under 10 levels.
#include <stddef.h>
#include "cJSON.h"

#define TSNET_JSON_MAX_DEPTH 32
// cJSON allocates a node for every value, about 50 to 60 bytes, so 2 MB of `[1,1,1,...` would make a 60 MB tree.
// 200,000 values (about 12 MB) holds a map message for over a thousand peers, at about 60 values a peer.
#define TSNET_JSON_MAX_VALUES 200000

// cJSON_ParseWithLength, or NULL for JSON nested deeper than TSNET_JSON_MAX_DEPTH, with more than TSNET_JSON_MAX_VALUES
// values (or that doesn't parse).
cJSON *tsnet_json_parse(const char *json, size_t len);
