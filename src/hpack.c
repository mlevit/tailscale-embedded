// HPACK (RFC 7541) for tsnet's HTTP/2 client. See hpack.h; section numbers are the RFC's.
#include "hpack.h"
#include <string.h>
#include "hpack_tables.h"

#define STATIC_N 61
#define ENTRY_OVERHEAD 32 // 4.1

void tsnet_hpack_dec_init(tsnet_hpack_dec_t *d, uint32_t max)
{
    d->max = d->size = max < TSNET_HPACK_TABLE_MAX ? max : TSNET_HPACK_TABLE_MAX;
    d->used = 0;
    d->n = 0;
}

// 5.1: an integer with an N-bit prefix. Values over 2^31 - 1 are refused (no length, index or size can be that big).
static int get_int(const uint8_t **p, const uint8_t *end, int prefix, uint32_t *out)
{
    if (*p >= end) {
        return -1;
    }
    uint32_t mask = (1u << prefix) - 1;
    uint64_t v = **p & mask;
    (*p)++;
    if (v < mask) {
        *out = (uint32_t)v;
        return 0;
    }
    for (int shift = 0; shift <= 28; shift += 7) {
        if (*p >= end) {
            return -1;
        }
        uint8_t b = *(*p)++;
        v += (uint64_t)(b & 0x7f) << shift;
        if (v > 0x7fffffff) {
            return -1;
        }
        if (!(b & 0x80)) {
            *out = (uint32_t)v;
            return 0;
        }
    }
    return -1; // more continuation bytes than any 31-bit value needs
}

int tsnet_hpack_huffman_decode(char *out, size_t cap, const uint8_t *in, size_t len)
{
    // Canonical decoding: the code read so far, its length, the first code of that length, and the index in
    // HPACK_HUFF_SYMS of that length's first symbol.
    uint32_t code = 0, first = 0;
    unsigned bits = 0, index = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        for (int b = 7; b >= 0; b--) {
            code = code << 1 | ((in[i] >> b) & 1);
            bits++;
            uint32_t count = HPACK_HUFF_COUNT[bits];
            if (code - first < count) {
                uint16_t sym = HPACK_HUFF_SYMS[index + (code - first)];
                if (sym == 256 || n >= cap) {
                    return -1; // 5.2: EOS in a string is an error
                }
                out[n++] = (char)sym;
                code = first = 0;
                bits = index = 0;
            } else {
                index += count;
                first = (first + count) << 1;
                if (bits == 30) {
                    return -1; // no code is longer (it would only be EOS's 30 ones, refused above)
                }
            }
        }
    }
    // 5.2: what's left is padding: at most 7 bits, all ones (EOS's start).
    if (bits > 7 || code != (1u << bits) - 1) {
        return -1;
    }
    return (int)n;
}

// 5.2: a string literal into dst (NUL-terminated).
static int get_string(const uint8_t **p, const uint8_t *end, char *dst, size_t *out_len)
{
    if (*p >= end) {
        return -1;
    }
    int huffman = **p & 0x80;
    uint32_t len;
    if (get_int(p, end, 7, &len) != 0 || len > (size_t)(end - *p)) {
        return -1;
    }
    int n;
    if (huffman) {
        n = tsnet_hpack_huffman_decode(dst, TSNET_HPACK_STRING_MAX, *p, len);
    } else {
        n = len <= TSNET_HPACK_STRING_MAX ? (int)len : -1;
        if (n >= 0) {
            memcpy(dst, *p, len);
        }
    }
    if (n < 0) {
        return -1;
    }
    dst[n] = '\0';
    *out_len = (size_t)n;
    *p += len;
    return 0;
}

// 4.4: drops the oldest entries until the table fits `size`.
static void evict_to(tsnet_hpack_dec_t *d, uint32_t size)
{
    size_t drop = 0, bytes = 0;
    while (drop < d->n && d->used > size) {
        const tsnet_hpack_entry_t *e = &d->entries[drop];
        d->used -= e->name_len + e->value_len + ENTRY_OVERHEAD;
        bytes += e->name_len + e->value_len;
        drop++;
    }
    if (drop == 0) {
        return;
    }
    size_t keep = d->n - drop;
    size_t total = keep ? d->entries[d->n - 1].off + d->entries[d->n - 1].name_len + d->entries[d->n - 1].value_len : 0;
    memmove(d->arena, d->arena + bytes, total ? total - bytes : 0);
    memmove(d->entries, d->entries + drop, keep * sizeof d->entries[0]);
    for (size_t i = 0; i < keep; i++) {
        d->entries[i].off = (uint16_t)(d->entries[i].off - bytes);
    }
    d->n = keep;
}

// 4.4: adds an entry, evicting first; one bigger than the table just empties it.
static void insert(tsnet_hpack_dec_t *d, const char *name, size_t name_len, const char *value, size_t value_len)
{
    uint32_t size = (uint32_t)(name_len + value_len + ENTRY_OVERHEAD);
    if (size > d->size) {
        evict_to(d, 0);
        return;
    }
    evict_to(d, d->size - size);
    size_t off = d->n ? d->entries[d->n - 1].off + d->entries[d->n - 1].name_len + d->entries[d->n - 1].value_len : 0;
    memcpy(d->arena + off, name, name_len); // fits: the bytes stored are at most used - 32n <= size
    memcpy(d->arena + off + name_len, value, value_len);
    d->entries[d->n++] = (tsnet_hpack_entry_t){(uint16_t)off, (uint16_t)name_len, (uint16_t)value_len};
    d->used += size;
}

// 2.3.3: index 1 to 61 is the static table, then the dynamic table newest first. Copies the entry's name (and value) into
// the decoder's buffers, which an insert can't then disturb.
static int lookup(tsnet_hpack_dec_t *d, uint32_t index, size_t *name_len, size_t *value_len)
{
    if (index == 0) {
        return -1;
    }
    if (index <= STATIC_N) {
        *name_len = strlen(HPACK_STATIC[index - 1][0]);
        memcpy(d->name, HPACK_STATIC[index - 1][0], *name_len + 1);
        if (value_len) {
            *value_len = strlen(HPACK_STATIC[index - 1][1]);
            memcpy(d->value, HPACK_STATIC[index - 1][1], *value_len + 1);
        }
        return 0;
    }
    if (index - STATIC_N > d->n) {
        return -1;
    }
    const tsnet_hpack_entry_t *e = &d->entries[d->n - (index - STATIC_N)];
    memcpy(d->name, d->arena + e->off, e->name_len);
    d->name[e->name_len] = '\0';
    *name_len = e->name_len;
    if (value_len) {
        memcpy(d->value, d->arena + e->off + e->name_len, e->value_len);
        d->value[e->value_len] = '\0';
        *value_len = e->value_len;
    }
    return 0;
}

int tsnet_hpack_decode(tsnet_hpack_dec_t *d, const uint8_t *block, size_t len, tsnet_hpack_field_fn fn, void *ctx)
{
    const uint8_t *p = block, *end = block + len;
    int fields = 0;
    while (p < end) {
        uint8_t b = *p;
        uint32_t index;
        size_t name_len, value_len;
        if (b & 0x80) { // 6.1: indexed field
            if (get_int(&p, end, 7, &index) != 0 || lookup(d, index, &name_len, &value_len) != 0) {
                return -1;
            }
        } else if ((b & 0xe0) == 0x20) { // 6.3: dynamic table size update, only before the block's first field (4.2)
            if (fields > 0 || get_int(&p, end, 5, &index) != 0 || index > d->max) {
                return -1;
            }
            d->size = index;
            evict_to(d, index);
            continue;
        } else { // 6.2: a literal, with incremental indexing (01), without (0000) or never indexed (0001)
            int incremental = (b & 0xc0) == 0x40;
            if (!incremental && (b & 0xe0) != 0x00) {
                return -1;
            }
            if (get_int(&p, end, incremental ? 6 : 4, &index) != 0) {
                return -1;
            }
            if (index == 0) {
                if (get_string(&p, end, d->name, &name_len) != 0) {
                    return -1;
                }
            } else if (lookup(d, index, &name_len, NULL) != 0) {
                return -1;
            }
            if (get_string(&p, end, d->value, &value_len) != 0) {
                return -1;
            }
            fn(ctx, d->name, name_len, d->value, value_len);
            fields++;
            if (incremental) {
                insert(d, d->name, name_len, d->value, value_len);
            }
            continue;
        }
        fn(ctx, d->name, name_len, d->value, value_len);
        fields++;
    }
    return 0;
}

// 5.1 encoding.
static int put_int(uint8_t *out, size_t cap, size_t *len, int prefix, uint8_t first, uint32_t v)
{
    uint32_t mask = (1u << prefix) - 1;
    if (*len >= cap) {
        return -1;
    }
    if (v < mask) {
        out[(*len)++] = (uint8_t)(first | v);
        return 0;
    }
    out[(*len)++] = (uint8_t)(first | mask);
    v -= mask;
    while (v >= 0x80) {
        if (*len >= cap) {
            return -1;
        }
        out[(*len)++] = (uint8_t)(0x80 | (v & 0x7f));
        v >>= 7;
    }
    if (*len >= cap) {
        return -1;
    }
    out[(*len)++] = (uint8_t)v;
    return 0;
}

static int put_string(uint8_t *out, size_t cap, size_t *len, const char *s)
{
    size_t n = strlen(s);
    if (put_int(out, cap, len, 7, 0x00, (uint32_t)n) != 0 || n > cap - *len) {
        return -1;
    }
    memcpy(out + *len, s, n);
    *len += n;
    return 0;
}

int tsnet_hpack_encode(uint8_t *out, size_t cap, size_t *len, const char *name, const char *value)
{
    size_t start = *len;
    uint32_t name_index = 0;
    for (uint32_t i = 0; i < STATIC_N; i++) {
        if (strcmp(HPACK_STATIC[i][0], name) == 0) {
            if (strcmp(HPACK_STATIC[i][1], value) == 0) {
                return put_int(out, cap, len, 7, 0x80, i + 1); // 6.1: the whole field is in the static table
            }
            if (name_index == 0) {
                name_index = i + 1;
            }
        }
    }
    // 6.2.2: a literal without indexing, the name by index or literal.
    int r = put_int(out, cap, len, 4, 0x00, name_index);
    if (r == 0 && name_index == 0) {
        r = put_string(out, cap, len, name);
    }
    if (r == 0) {
        r = put_string(out, cap, len, value);
    }
    if (r != 0) {
        *len = start;
    }
    return r;
}
