#pragma once
// lwIP's options for tsnet's host tests and tools: ESP-IDF's own lwIP sources (components/lwip/lwip), built
// with NO_SYS (no threads: tsnet's event loop drives its timers, sys_check_timeouts), IPv4 only, raw API and no
// Ethernet. The tailnet's netif is routed to by its subnet (100.64.0.0/10), never made the default, as on the device. ESP_LWIP stays undefined, so esp-lwip's patches are off: stock lwIP.
#define NO_SYS 1
#define LWIP_TIMERS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_ACD 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_ICMP 1
#define LWIP_RAW 1
#define LWIP_UDP 1
#define LWIP_TCP 1
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define LWIP_STATS 0
#define LWIP_HAVE_LOOPIF 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_SINGLE_NETIF 0 // route by subnet, as on the device (with one netif, lwIP would send all to the default)
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#define MEM_ALIGNMENT 8
#define TCP_MSS 1240                  // the TUN MTU (1280) less the IPv4 and TCP headers
#define TCP_WND (4 * TCP_MSS)
#define TCP_SND_BUF (4 * TCP_MSS)
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_CHKSUM_ALGORITHM 3
#define LWIP_DEBUG 0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1 // the C library's htons and friends, not lwIP's macros over them
