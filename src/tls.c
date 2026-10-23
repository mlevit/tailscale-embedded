// TLS for the dial. See tls.h.
#include "tls.h"
#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h" // the error codes only
#include "platform.h"
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return tsnet_random(out, len) == 0 ? 0 : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    int n = tsnet_sock_write(*(int *)ctx, buf, len);
    return n > 0 ? n : n == 0 ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    int n = tsnet_sock_read(*(int *)ctx, buf, len);
    return n > 0 ? n : n == 0 ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}

static void log_err(const char *what, int ret)
{
    char text[96];
    mbedtls_strerror(ret, text, sizeof text);
    tsnet_log(TSNET_LOG_WARN, "TLS %s: %s (-0x%04x)", what, text, (unsigned)-ret);
}

int tsnet_tls_start(tsnet_tls_t *t, int fd, const char *host, tsnet_tls_trust_t trust)
{
    memset(t, 0, sizeof *t);
    t->fd = fd;
#if defined(MBEDTLS_PSA_CRYPTO_C)
    psa_crypto_init(); // TLS 1.3 needs PSA; a no-op once done
#endif
    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    int ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret == 0) {
        // TLS 1.2 only, as the device's mbedTLS is built (its sdkconfig leaves CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 off), so
        // the host tests speak what the device speaks. TLS 1.3 also can't reach Tailscale's DERP servers with mbedTLS
        // 3.6: they end their chain with an Ed25519 "meta certificate" (derphttp parseMetaCert), and mbedTLS's TLS 1.3
        // client fails a chain whose last certificate has an algorithm it skips (ssl_tls13_parse_certificate returns the
        // skipped parse's error; its TLS 1.2 code returns 0). Seen 2026-10-23 against derp1f.tailscale.com.
        // Lift this once mbedTLS fixes that and the device's sdkconfig turns TLS 1.3 on.
        mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
        // OPTIONAL completes the handshake whatever the certificate, and tsnet_tls_handshake then applies the policy.
        mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_rng(&t->conf, rng, NULL);
        if (tsnet_tls_trust(&t->conf) != 0) {
            tsnet_log(TSNET_LOG_WARN, "TLS: no certificate authorities");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
    }
    if (ret == 0) {
        ret = mbedtls_ssl_set_hostname(&t->ssl, host);
    }
    if (ret != 0) {
        if (ret < -1) {
            log_err("setup", ret);
        }
        tsnet_tls_free(t);
        return -1;
    }
    t->trust = trust;
    mbedtls_ssl_set_bio(&t->ssl, &t->fd, bio_send, bio_recv, NULL);
    return 0;
}

int tsnet_tls_handshake(tsnet_tls_t *t)
{
    if (t->done) {
        return 1;
    }
    int ret = mbedtls_ssl_handshake(&t->ssl);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    if (ret != 0) {
        log_err("handshake", ret);
        return -1;
    }
    uint32_t flags = mbedtls_ssl_get_verify_result(&t->ssl);
    if (flags != 0) {
        char why[160];
        mbedtls_x509_crt_verify_info(why, sizeof why, "", flags);
        size_t n = strlen(why);
        while (n > 0 && why[n - 1] == '\n') {
            why[--n] = '\0';
        }
        if (t->trust == TSNET_TLS_VERIFY) {
            tsnet_log(TSNET_LOG_WARN, "TLS certificate refused: %s", why);
            return -1;
        }
        // controlhttp: "warning: TLS cert verification ... failed", and it carries on.
        tsnet_log(TSNET_LOG_WARN, "TLS certificate not verified (Noise protects this connection): %s", why);
    }
    t->done = 1;
    return 1;
}

int tsnet_tls_read(tsnet_tls_t *t, void *buf, size_t len)
{
    int ret = mbedtls_ssl_read(&t->ssl, buf, len);
    if (ret > 0) {
        return ret;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
    if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { // a TLS 1.3 ticket, not data
        return 0;
    }
#endif
    if (ret != 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        log_err("read", ret);
    }
    return -1;
}

int tsnet_tls_write(tsnet_tls_t *t, const void *buf, size_t len)
{
    int ret = mbedtls_ssl_write(&t->ssl, buf, len);
    if (ret > 0) {
        return ret;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    log_err("write", ret);
    return -1;
}

void tsnet_tls_free(tsnet_tls_t *t)
{
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
}
