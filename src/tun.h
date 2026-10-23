#pragma once
// The tunnel's IP side: net/tstun's role between WireGuard (wgdev.h) and an IP stack, here lwIP's netif on
// the node's tailnet address. One file for both builds: on the host, ESP-IDF's lwIP with NO_SYS (test/lwip), which
// feeds packets to ip_input; on the device, ESP-IDF's lwIP in its tcpip thread, which takes them with tcpip_input.
//   - Threads: tsnet's task calls everything here. The netif and the out queue are touched only in lwIP's
//     context, through tsnet_ip_exec (platform.h). The netif's output runs there and wakes tsnet's loop through
//     tsnet_tun_fd.
//   - In: wgdev's deliver hands a decrypted packet here. A source outside the peer's own AllowedIPs is dropped
//     (AllowedPeerSourceIP), and so are TSMP and what the packet filter refuses (filter.h). A refused TCP SYN
//     gets a TSMP reject back. The rest is queued and fed to lwIP by step, after wgdev has returned.
//   - Out: lwIP's output is copied and queued. Step runs each packet through the filter (which records UDP flows),
//     then routes it by its destination (AllowedIPs' longest match) to the peer's WireGuard, or drops it when no peer
//     has the address.
//   - The netif's MTU is the TUN MTU (1280); its address is the node's, with Tailscale's 100.64.0.0/10 as the
//     subnet, so lwIP routes the tailnet to it.
// IPv4 only for now. At most TSNET_TUN_QUEUE packets wait in each direction; past that the newest is dropped.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "allowedips.h"
#include "filter.h"
#include "lwip/netif.h"
#include "tailcfg.h"

#define TSNET_TUN_QUEUE 64

typedef struct tsnet_tun tsnet_tun_t;

typedef struct {
    void *ctx;
    // An IP packet for the peer `peer` (to tsnet_wgdev_send).
    void (*send)(void *ctx, const uint8_t peer[32], const uint8_t *pkt, size_t len);
    // How lwIP takes a packet: ip_input with NO_SYS, tcpip_input on the device.
    netif_input_fn input;
} tsnet_tun_cfg_t;

tsnet_tun_t *tsnet_tun_new(const tsnet_tun_cfg_t *cfg);
void tsnet_tun_free(tsnet_tun_t *t);

// The node's tailnet IPv4 address (the netmap's self node). The netif comes up with it.
int tsnet_tun_set_addr(tsnet_tun_t *t, const uint8_t ip4[4]);
// A peer's routes (its netmap AllowedIPs), replacing what it had. -1 for no memory.
int tsnet_tun_set_routes(tsnet_tun_t *t, const uint8_t peer[32], const tsnet_prefix_t *routes, size_t n);
void tsnet_tun_remove_peer(tsnet_tun_t *t, const uint8_t peer[32]);
// A jailed peer (the netmap's IsJailed): its packets get the jailed filter, so it can't open a connection to this
// node. -1 for no memory.
int tsnet_tun_set_jailed(tsnet_tun_t *t, const uint8_t peer[32], bool jailed);
// The packet filter's rules and the node's own addresses, from each netmap (tsnet_filter_set). Until the first
// call, every inbound packet is dropped.
int tsnet_tun_set_filter(tsnet_tun_t *t, const char *rules_json, const tsnet_prefix_t *local, size_t n_local);

// wgdev's deliver: a decrypted packet from `peer`.
void tsnet_tun_deliver(tsnet_tun_t *t, const uint8_t peer[32], const uint8_t *pkt, size_t len);
// Feeds what's queued: packets in to lwIP, packets out to WireGuard.
void tsnet_tun_step(tsnet_tun_t *t);
// Packets wait to go in to lwIP: the loop shouldn't sleep.
bool tsnet_tun_pending(const tsnet_tun_t *t);
// Readable in tsnet_poll while lwIP has packets waiting to go out: then the loop calls step.
int tsnet_tun_fd(const tsnet_tun_t *t);
