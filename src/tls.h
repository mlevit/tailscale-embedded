#pragma once
// TLS for the dial: mbedTLS over a non-blocking socket. Two trust policies, both Tailscale's:
// - TSNET_TLS_VERIFY: a bad certificate fails the connection. For the GET of the server's key
//   (controlclient loadServerPubKeys over net/tlsdial), which is what makes the Noise handshake trustworthy.
// - TSNET_TLS_LOG_ONLY: a bad certificate is logged and the connection goes on. For the /ts2021 upgrade on 443
//   (controlhttp tryURLUpgrade: "We don't actually care about the TLS security ... All they'll see is some Noise").
// No ALPN: controlhttp clears NextProtos, since HTTP/2 can't switch protocols.
#include <stddef.h>
#include "mbedtls/ssl.h"

typedef enum { TSNET_TLS_VERIFY, TSNET_TLS_LOG_ONLY } tsnet_tls_trust_t;

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int fd;
    tsnet_tls_trust_t trust;
    int done; // the handshake finished
} tsnet_tls_t;

// Sets up a client for `host` (SNI and the name checked) on a connected socket. Returns 0 or -1.
int tsnet_tls_start(tsnet_tls_t *t, int fd, const char *host, tsnet_tls_trust_t trust);
// Moves the handshake on: 1 once finished, 0 while it waits for the socket, -1 if it failed.
int tsnet_tls_handshake(tsnet_tls_t *t);
// As tsnet_sock_read/write: bytes moved (> 0), 0 if none can move now, -1 if closed or failed.
int tsnet_tls_read(tsnet_tls_t *t, void *buf, size_t len);
int tsnet_tls_write(tsnet_tls_t *t, const void *buf, size_t len);
// Frees the TLS state (not the socket).
void tsnet_tls_free(tsnet_tls_t *t);
