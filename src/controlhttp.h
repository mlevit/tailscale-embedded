#pragma once
// The dial to the control server: Tailscale's control/controlhttp client. It POSTs the Noise initiation to /ts2021
// as an HTTP upgrade, on port 80 first and on 443 (TLS) 500 ms later, or at once if 80 fails; the first to finish the
// handshake wins (client.go dialHostOpt). Then the connection carries controlbase records.
//
// Not yet: the dial plan (DialPlan candidates from a map response), proxies, ACE, and the netcheck/DERP fallbacks of
// tailscaled's dialer; DNS is the platform's (no dnscache bootstrap).
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"
#include "platform.h"

typedef struct tsnet_ctrl_conn tsnet_ctrl_conn_t;

#define TSNET_NO_PORT (-1) // controlhttp.NoPort: don't try this one

// The ports to dial for a server URL, as ts2021.NewClient picks them. `https` is the URL's scheme, `port` its explicit
// port or 0. https with a port: HTTP on 80 still, HTTPS on the port. http with a port: HTTP on it, HTTPS on 443 unless
// the host is private. http without a port on a private host: 80 only. Otherwise 80 and 443. Private is a loopback or
// private IP address (RFC 1918, fc00::/7) or "localhost". Pure.
void tsnet_ts2021_ports(int https, const char *host, uint16_t port, int *http_port, int *https_port);

// Dials `host` as Tailscale's client does. `http_port` and `https_port` are the Dialer's HTTPPort and HTTPSPort: 0 for
// 80 and 443, TSNET_NO_PORT to leave one out (no HTTP is controlhttp's forceNoise443). Each attempt makes its own
// handshake with a fresh ephemeral key (dialURL). Gives up after `timeout_ms`. Returns the connection, or NULL (the
// reason is logged).
// It blocks its caller (its own poll loop over the calls below); the control client's event loop uses those directly.
// shortcut: DNS (getaddrinfo) blocks while an attempt starts; a non-blocking resolver is a later step.
tsnet_ctrl_conn_t *tsnet_controlhttp_dial(const char *host, int http_port, int https_port,
                                          const uint8_t machine_priv[TSNET_KEY_LEN],
                                          const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version, int timeout_ms);

// The same dial, step by step, for an event loop: start it, then call step whenever its sockets are ready or
// tsnet_dial_wait_ms has passed, until step says it's done.
//
// A dial less than 2 minutes after the previous one skips port 80 and starts on the HTTPS port at once, when there is
// one (controlhttp forceNoise443 with health's LastNoiseDialWasRecent): a quick retry assumes port 80 is what failed.
typedef struct tsnet_dial tsnet_dial_t;
tsnet_dial_t *tsnet_dial_start(const char *host, int http_port, int https_port, const uint8_t machine_priv[TSNET_KEY_LEN],
                               const uint8_t control_pub[TSNET_KEY_LEN], uint16_t version, int timeout_ms);
// 1 when an attempt has won (take it), -1 when every attempt failed or the time ran out, 0 while it goes on.
int tsnet_dial_step(tsnet_dial_t *d);
// The sockets to wait on (at most 2), and how long to wait at most before stepping again.
int tsnet_dial_poll(const tsnet_dial_t *d, tsnet_poll_t p[2]);
int tsnet_dial_wait_ms(const tsnet_dial_t *d);
tsnet_ctrl_conn_t *tsnet_dial_take(tsnet_dial_t *d);
void tsnet_dial_free(tsnet_dial_t *d);
// Forgets the previous dial's time, so the next dial tries port 80 again (for tests).
void tsnet_dial_forget_recent(void);

// The port the connection went over.
uint16_t tsnet_ctrl_port(const tsnet_ctrl_conn_t *c);
// One record's plaintext into `pt` (`cap` at least TSNET_NOISE_MAX_PLAINTEXT): its length (> 0), 0 if none is in yet,
// -1 if the connection failed or a record didn't decrypt.
int tsnet_ctrl_read(tsnet_ctrl_conn_t *c, uint8_t *pt, size_t cap);
// Waits up to `timeout_ms` for something to read: 1 if there is, 0 if not, -1 on error.
int tsnet_ctrl_wait(tsnet_ctrl_conn_t *c, int timeout_ms);
// Sends `len` bytes as records of at most 4077 (conn.go Write), waiting until the socket took everything (up to 10 s).
// Returns 0, or -1. For tools and tests; the event loop uses tsnet_ctrl_write_some.
int tsnet_ctrl_write(tsnet_ctrl_conn_t *c, const uint8_t *data, size_t len);
// Takes up to one record's worth (4077 bytes) without waiting: seals it, sends what the socket takes, and keeps the
// rest queued. Returns how many bytes it took (0 while a record is still queued), or -1 on an error.
int tsnet_ctrl_write_some(tsnet_ctrl_conn_t *c, const uint8_t *data, size_t len);
// Sends what's left of a queued record: 1 when none is left, 0 when the socket is full, -1 on an error.
int tsnet_ctrl_flush(tsnet_ctrl_conn_t *c);
int tsnet_ctrl_pending_write(const tsnet_ctrl_conn_t *c); // a record is queued: wait for the socket to be writable
int tsnet_ctrl_buffered(const tsnet_ctrl_conn_t *c);      // bytes already read are waiting: read before polling
int tsnet_ctrl_fd(const tsnet_ctrl_conn_t *c);
void tsnet_ctrl_close(tsnet_ctrl_conn_t *c);
