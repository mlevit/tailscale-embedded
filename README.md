# tailscale-embedded

A Tailscale node for microcontrollers, in C. It registers with Tailscale's control server (or headscale), keeps its
netmap, finds paths to peers over DERP and disco, and runs WireGuard into lwIP behind the tailnet's packet filter. Each
behaviour is ported from the official client's source (Tailscale v1.104.1, wireguard-go and Go's HTTP/2), and the
code cites the function it follows.

**Not affiliated with or endorsed by Tailscale Inc.** "Tailscale" is their trademark. This is an independent client.

## Status

- **Runs on an ESP32-P4** (an M5Stack Tab5, ESP-IDF 5.5) against Tailscale's own service, as a device's only network
  path to its tailnet: it registers, takes a direct path to a peer, and logs in again with its stored key after restarts and OTA updates.
  No other chip has run it yet.
- **Host tests** on macOS and Linux: 30 suites under ASan and UBSan, with the official test vectors where they exist
  and a mutation fuzzer over the network parsers.
- **Conformance harness**: headscale v0.29.5 and a real `tailscaled` v1.104.1 in Docker, eleven scenarios
  (join, restart, peers, a stalled server, removal, DERP, relays, netcheck, blocked UDP, disco, and WireGuard both
  ways through the packet filter). See [harness/](harness/README.md).
- Early: the API can change, and it hasn't had an outside security review. See [SECURITY.md](SECURITY.md).

## What it does

| Part | Follows |
|---|---|
| Noise IK transport and HTTP/2 to control | `control/controlbase`, `controlhttp`, Go's `net/http2` |
| Registration, the map poll, netmap deltas (zstd) | `control/controlclient`, `tailcfg` |
| DERP: home region, other regions, reconnects | `derp`, `derphttp`, magicsock's `derp.go` |
| netcheck: STUN, region latency, the DERP home | `net/netcheck`, `net/stun` |
| Disco: pings, CallMeMaybe, path selection | `disco`, `wgengine/magicsock` |
| WireGuard: handshakes, rekeying, timers | `wireguard-go/device` |
| The packet filter, jailed peers, TSMP rejects | `wgengine/filter`, `net/tstun` |
| The node in one call | `tsnet.Server` |

## Limits

- **IPv4 only**, on the tailnet and underneath it.
- **Peers:** every peer in the netmap is a WireGuard peer, set up front (the official client sets them up lazily). Each
  gets only its own Tailscale addresses: no exit node, no subnet routes.
- **Filter:** rules that grant peer capabilities (`cap:` sources) never match, so they drop.
- **Not implemented:** tailnet lock, MagicDNS resolution (look peers up with `tsnet_netmap_peer_by_name`), port mapping
  (UPnP, NAT-PMP, PCP), Taildrop, SSH, serve and funnel, HTTPS certificates.
- **The capability version is 131.** Some of what it promises isn't implemented yet: PingRequest's disco, TSMP, ICMP
  and peerapi pings, c2n requests, peer-relay disco messages, and seamless key renewal.
- **TLS 1.2 on the device.** mbedTLS 3.6's TLS 1.3 client fails Tailscale's DERP certificate chains.

## Using it with ESP-IDF

Add the repository as a component: clone it into your project's `components/`, or list it in `EXTRA_COMPONENT_DIRS`.
[examples/esp-idf](examples/esp-idf) is a complete app: it brings the network up, sets the clock and starts the node.

```c
tsnet_server_cfg_t cfg = {
    .client = {
        .server_url = "https://controlplane.tailscale.com",
        .auth_key = "tskey-auth-...", // only to register; NULL logs a login URL instead
        .hostname = "my-device",
        .ipn_version = "my-app-1.0", .os = "linux", .os_version = "ESP-IDF", .machine = "esp32p4",
    },
    .input = tcpip_input,
    .on_state = on_state,
    .on_netmap = on_netmap,
};
tsnet_server_t *srv = tsnet_server_new(&cfg);
// Then, in one task: tsnet_server_poll, tsnet_poll, tsnet_server_step, in a loop.
```

What the device build needs (PSRAM, mbedTLS options, lwIP sizes, the task's stack) is in
[docs/design.md](docs/design.md#on-the-device), and the example's `sdkconfig.defaults` sets all of it.

- **Set the clock first.** TLS checks certificate dates, and peers refuse a WireGuard handshake dated earlier than the
  last one they took from the node.
- **Keys are in NVS in plaintext.** Turn on flash encryption and NVS encryption for a device that leaves your hands.
- **An auth key in an image makes the image a secret.** Build release images without one: a registered node logs in
  with its stored key.

## Porting

The core (`src/`) is portable C11 with no ESP-IDF calls. Everything system-specific goes through
[src/platform.h](src/platform.h): time, randomness, sockets, key storage, a wake-up, and running code in lwIP's
context. `platform/esp/` is the ESP-IDF back end, `platform/host/` the POSIX one, which the tests use. A new platform
needs those calls plus mbedTLS 3.6, lwIP and cJSON.

## Tests

```sh
test/test.sh                    # host tests (macOS or Linux; downloads mbedTLS, cJSON and lwIP, sha256-checked)
harness/harness.sh up           # the conformance harness (Docker)
TSNET_HARNESS=1 test/test.sh    # the tests, then the eleven scenarios against it (about 12 minutes)
harness/harness.sh down
TSNET_LIVE=1 test/test.sh       # also checks against Tailscale's live control and DERP servers
```

With `IDF_PATH` set, the tests use ESP-IDF's own copies of mbedTLS, cJSON and lwIP instead of downloading them.

## Layout

| Path | What |
|---|---|
| `src/` | the portable core, one module per Tailscale package; each header says what it follows |
| `platform/` | the ESP-IDF and POSIX back ends |
| `test/` | host tests, fixtures, and the tools the harness runs |
| `harness/` | headscale and tailscaled in Docker |
| `tools/` | the scripts that made the test vectors (Python with pinned independent libraries, such as PyNaCl) |
| `third_party/` | zstd's decoder, Monocypher and TweetNaCl, unmodified |
| `docs/design.md` | how each module works, what it follows, and what it doesn't do yet |

## License

MIT ([LICENSE](LICENSE)). The projects it follows, and the vendored libraries, keep their own licences:
[NOTICE](NOTICE).
