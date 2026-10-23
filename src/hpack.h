#pragma once
// HPACK (RFC 7541) for tsnet's HTTP/2 client. The decoder is complete: the static and dynamic tables, Huffman,
// size updates. The encoder writes only what a client needs and keeps no table (indexed static fields and literals
// without indexing, no Huffman), which any decoder must accept; Go's encoder indexes and uses Huffman, to save bytes.
// Pure and bounded: a failure is HTTP/2's COMPRESSION_ERROR, after which the connection is unusable.
#include <stddef.h>
#include <stdint.h>

#define TSNET_HPACK_TABLE_MAX 4096  // SETTINGS_HEADER_TABLE_SIZE's default, which Go's client keeps (no setting sent)
#define TSNET_HPACK_STRING_MAX 4096 // a name or value, after Huffman decoding (Go's limit is the header list's, 10 MB)

typedef struct {
    uint16_t off, name_len, value_len;
} tsnet_hpack_entry_t;

typedef struct {
    uint32_t max;  // the size we allow (SETTINGS_HEADER_TABLE_SIZE)
    uint32_t size; // the size the encoder chose (its last size update, at most max)
    uint32_t used; // the entries' size, each name + value + 32 (RFC 7541 4.1)
    tsnet_hpack_entry_t entries[TSNET_HPACK_TABLE_MAX / 32]; // oldest first
    size_t n;
    uint8_t arena[TSNET_HPACK_TABLE_MAX]; // the entries' bytes, in the same order
    char name[TSNET_HPACK_STRING_MAX + 1], value[TSNET_HPACK_STRING_MAX + 1];
} tsnet_hpack_dec_t;

// `max` is the table size we advertise, at most TSNET_HPACK_TABLE_MAX.
void tsnet_hpack_dec_init(tsnet_hpack_dec_t *d, uint32_t max);

// Called for each field of a block, in order. The strings are NUL-terminated for convenience, but may hold NULs: use
// the lengths. They are valid only during the call.
typedef void (*tsnet_hpack_field_fn)(void *ctx, const char *name, size_t name_len, const char *value, size_t value_len);

// Decodes one whole header block (HEADERS plus any CONTINUATION). Returns 0, or -1 (a COMPRESSION_ERROR).
int tsnet_hpack_decode(tsnet_hpack_dec_t *d, const uint8_t *block, size_t len, tsnet_hpack_field_fn fn, void *ctx);

// Decodes a Huffman-coded string (RFC 7541 5.2) into `out`. Returns its length, or -1 if it doesn't fit, holds EOS, or
// its padding is longer than 7 bits or not EOS's leading ones.
int tsnet_hpack_huffman_decode(char *out, size_t cap, const uint8_t *in, size_t len);

// Appends one field to a block being built at out[*len] (capacity `cap`). Returns 0, or -1 if it doesn't fit.
int tsnet_hpack_encode(uint8_t *out, size_t cap, size_t *len, const char *name, const char *value);
