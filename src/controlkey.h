#pragma once
// The control server's Noise key: controlclient loadServerPubKeys. GET https://<host>/key?v=<capver> over
// verified TLS returns tailcfg.OverTLSPublicKeyResponse, {"legacyPublicKey":"mkey:…","publicKey":"mkey:…"}; the Noise
// handshake uses publicKey, and a server without one can't be used (direct.go: serverNoiseKey.IsZero()).
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"
#include "platform.h"

// Parses the response body. Returns 0 with the key, or -1 (not JSON, no publicKey, not "mkey:" + 64 hex digits, or all
// zero). Pure.
int tsnet_control_key_parse(const char *body, size_t len, uint8_t pub[TSNET_KEY_LEN]);

// Fetches and parses it from host:port, over verified TLS for an https:// server URL or plain HTTP for http:// (as Go's
// HTTP client does with the server URL). Returns 0, or -1 (logged). With TLS, a certificate that doesn't verify fails it.
// It blocks its caller for up to `timeout_ms` (its own poll loop over the calls below), for tools and tests.
int tsnet_control_key_fetch(const char *host, uint16_t port, int use_tls, uint16_t version, uint8_t pub[TSNET_KEY_LEN],
                            int timeout_ms);

// The same fetch, step by step, for an event loop (as the dial's, controlhttp.h): step when the socket is ready or
// tsnet_keyfetch_wait_ms has passed, until it says it's done.
typedef struct tsnet_keyfetch tsnet_keyfetch_t;
tsnet_keyfetch_t *tsnet_keyfetch_start(const char *host, uint16_t port, int use_tls, uint16_t version, int timeout_ms);
int tsnet_keyfetch_step(tsnet_keyfetch_t *k); // 1 the key is in, -1 failed (logged), 0 going on
int tsnet_keyfetch_poll(const tsnet_keyfetch_t *k, tsnet_poll_t *p); // the socket to wait on (0 or 1)
int tsnet_keyfetch_wait_ms(const tsnet_keyfetch_t *k);
void tsnet_keyfetch_key(const tsnet_keyfetch_t *k, uint8_t pub[TSNET_KEY_LEN]);
void tsnet_keyfetch_free(tsnet_keyfetch_t *k);
