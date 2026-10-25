# Design notes

How tailscale-embedded is built, module by module, and why. The [README](../README.md) is the short version.

## Rules for working here

- **Every behaviour comes from Tailscale's source, cited where it is used** (a file in tailscale/tailscale or
  wireguard-go, and the function or constant). Not from another client, and not from memory. If the source and this code
  disagree, the code is wrong.
- **The core is portable C with no ESP-IDF calls.** Everything system-specific goes through `src/platform.h`, which has
  two back ends: `platform/esp/` (ESP-IDF) and `platform/host/` (macOS and Linux, for tests and the conformance
  harness). A module that needs more of the system (sockets, storage) adds it to `platform.h` with both back ends.
- **No hand-written crypto.** X25519 and ChaCha20-Poly1305 are mbedTLS's (the same library on the device and in host
  tests); BLAKE2s is RFC 7693's algorithm; HMAC and HKDF are the RFC 2104 and Noise constructions over it; Ed25519 is
  Monocypher's; NaCl box's HSalsa20 and XSalsa20-Poly1305 are TweetNaCl's. New primitives come from a vetted library,
  with the RFC's vectors in a test.
- **Every module has host tests under ASan and UBSan** (`test/`), with the official test vectors where they exist,
  and later the conformance harness against headscale and a real `tailscaled`.
- **A parser of anything from the network is bounded and fuzz-shaped in its tests** (every split point, truncation,
  garbage), as any parser of untrusted input should be.

## Modules

| Module | Tailscale source |
|---|---|
| Platform layer, crypto | RFC 7748, 8439, 7693; Noise section 4.3 |
| Conformance harness | headscale v0.29.5, tailscale v1.104.1 ([harness/](../harness/README.md)) |
| Noise IK transport | `control/controlbase`, `controlhttp`, `ts2021` |
| HTTP/2 client | Go `net/http2` as `ts2021` uses it; RFC 7541 |
| Control client and netmap | `control/controlclient`, `tailcfg` |
| DERP client | `derp`, `derphttp`, magicsock's `derp.go` |
| Endpoint discovery | `net/stun`, `net/netcheck` |
| Disco and path selection | `disco`, `wgengine/magicsock` |
| WireGuard and the IP side | `wireguard-go/device`, `wgengine`, `net/tstun`, `wgengine/filter` |
| The node in one call | `tsnet.Server` |

## What is here now

- `src/platform.h`: `tsnet_now_ms()` (monotonic), `tsnet_random()` (the system CSPRNG), `tsnet_log()`.
  - On the device: `esp_timer`, `esp_fill_random` and `esp_log`. `esp_fill_random` is true random on the ESP32-P4
    because ESP-IDF keeps the SAR ADC entropy source on from boot on a chip with no radio of its own
    (`docs/en/api-reference/system/random.rst`, "Startup"). An app that calls `bootloader_random_disable()` to use
    the ADC loses that.
  - On the host: `clock_gettime(CLOCK_MONOTONIC)`, `arc4random_buf` (macOS) or `getentropy` (Linux), stderr.
- `src/crypto.h`: `tsnet_x25519()` (refuses an all-zero result, i.e. a low-order point), `tsnet_x25519_public()`,
  `tsnet_aead_seal()`/`tsnet_aead_open()` (ChaCha20-Poly1305, 12-byte nonce; open zeroes the output on a bad tag),
  `tsnet_hmac_blake2s()`, `tsnet_hkdf()` (Noise's), `tsnet_wipe()`. `src/blake2s.h`: one-shot and incremental BLAKE2s.
  NaCl box, as Go's `nacl/box`: `tsnet_box_shared()` (`box.Precompute`: X25519, then HSalsa20 from the vendored
  TweetNaCl, `third_party/tweetnacl`), `tsnet_box_seal()`/`open()` (XSalsa20-Poly1305, the tag before the ciphertext, as Go and
  libsodium's `_easy` calls put it).
- `src/noise.h`: the client side of `control/controlbase`. `tsnet_noise_client_start()` makes the 101-byte
  initiation (version, type 1, length 96, ephemeral key, encrypted machine key, tag) after mixing in the prologue
  `Tailscale Control Protocol v<version>` and the server's key; `tsnet_noise_client_finish()` checks the 51-byte response
  (or reports the server's error message, type 3) and splits the keys, the client sending with the first.
  `tsnet_noise_seal()`/`open()` are the records: type 4, a big-endian length, at most 4077 bytes of plaintext, and a nonce
  of 4 zero bytes then the counter **big-endian** (`conn.go`; WireGuard's is little-endian), refused once it reaches
  `invalidNonce`. `tsnet_noise_framer_*` cuts the byte stream into frames, refusing one announced over 4096 bytes.
- `src/platform.h` also has TCP (`tsnet_tcp_connect()`, non-blocking, with `TCP_NODELAY` as Go's dialer sets it;
  `tsnet_sock_read/write/close()`, `tsnet_poll()`) in `platform/net_posix.c`, the same BSD calls on the host and lwIP,
  and `tsnet_tls_trust()`: ESP-IDF's certificate bundle on the device, the system's CA file on the host.
- `src/tls.h`: mbedTLS over a non-blocking socket with SNI and no ALPN, and **two trust policies, both Tailscale's**:
  `TSNET_TLS_VERIFY` for the control key (`net/tlsdial`: a bad certificate fails), `TSNET_TLS_LOG_ONLY` for the
  `/ts2021` upgrade on 443 (`controlhttp`: logged, then carried on, since Noise protects it). No baked-in ISRG Root X1
  (`bakedroots`): the device's full bundle has it. **TLS 1.2 only**, as the device's mbedTLS is built (its sdkconfig
  has no TLS 1.3), so the host tests speak what the device speaks. Go speaks TLS 1.3. mbedTLS 3.6's TLS 1.3 client also
  can't reach Tailscale's DERP servers: their chain ends with an Ed25519 meta certificate, and that client fails a
  chain whose last certificate has an algorithm it skips (its TLS 1.2 code doesn't).
- `src/http1.h`: base64, the upgrade request and a GET, and a bounded response reader (head ≤ 4 KB, Content-Length,
  chunked, or to the close) that stops at the end of the head, so the bytes after a 101 stay with the caller.
- `src/controlkey.h`: `GET /key?v=<capver>` over verified TLS for an `https://` server, plain HTTP for `http://`
  (`loadServerPubKeys`), and the parse of `publicKey`
  (`mkey:` + 64 hex digits; a missing or zero key fails, as the client can't do Noise without it). For an event loop
  it is `tsnet_keyfetch_start/step/poll/wait_ms`; `tsnet_control_key_fetch` is that, blocking, for tools.
- `src/controlhttp.h`: the dial (`client.go dialHostOpt`): port 80 first, 443 500 ms later or as soon as 80 fails, each
  attempt with its own handshake; the first to finish wins and the other is closed. The ports are the Dialer's
  `HTTPPort`/`HTTPSPort` (0 for the defaults, `TSNET_NO_PORT` to leave one out).
  - A dial less than 2 minutes after the previous one skips port 80 and starts on the HTTPS port at once
    (`forceNoise443`, `health.LastNoiseDialWasRecent`): a quick retry assumes a middlebox broke port 80. Without an
    HTTPS port (an `http://` URL on a private host), port 80 is still used.
  - For an event loop: `tsnet_dial_start/step/poll/wait_ms/take`, and on the connection
    `tsnet_ctrl_write_some`. It takes one record's worth, sends what the socket takes and keeps the rest queued; nothing
    new is taken while a record waits, as mbedTLS wants a retried write to repeat its data. Also `tsnet_ctrl_flush`,
    `pending_write`, `buffered` and `fd`. `tsnet_controlhttp_dial` and `tsnet_ctrl_write` are the blocking forms, for
    tools and tests.
  - Not yet: the dial plan from a map response, proxies, tailscaled's DNS fallbacks. DNS (getaddrinfo) still blocks
    while an attempt starts.
- `src/hpack.h`: RFC 7541. The decoder is complete (static and dynamic tables, Huffman, size updates) with a
  4096-byte table, the default Go's client keeps, and names and values of at most 4 KB each. The encoder keeps no table:
  an indexed static field, or a literal without indexing and without Huffman, which every decoder accepts (Go's
  encoder indexes and compresses to save bytes). `src/hpack_tables.h` (the static table and the canonical Huffman code)
  is generated from the RFC's text by `tools/hpack_tables.py`, which checks the code is canonical.
- `src/h2.h`: the HTTP/2 client, Go's `x/net/http2` Transport as `control/ts2021` uses it. Pure: bytes in
  (`tsnet_h2_feed`), bytes out (`tsnet_h2_pending`/`sent`), callbacks per response (field, head, data, end). It first
  reads ts2021's optional early payload (`\xff\xff\xffTS`, a 4-byte length, the JSON `tailcfg.EarlyNoise`), checks it
  parses and drops it: nothing in Tailscale's client reads it (only its tests call `GetEarlyPayload`). Then as Go:
  - Its SETTINGS: ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 4 MB and MAX_FRAME_SIZE 1 MB, plus a 1 GB connection
    WINDOW_UPDATE. Flow control comes back by `inflow.add`'s rule (a 4 KB minimum, or doubling the window).
  - Streams: odd stream ids, requests in `encodeRequestHeaders`' order (`:scheme https`, as ts2021 requests
    `https://host/path`).
  - Frames: PINGs answered and none sent (ts2021 sets no `ReadIdleTimeout`). A GOAWAY ends only the streams it doesn't
    cover. A connection error is answered with GOAWAY, and `frame.go`'s checks on every frame type apply.
  - The header block of a stream we cancelled is still decoded, so HPACK's table stays in step.
  - DATA is streamed to the callback, not buffered, so the big windows cost no memory.
  - Different for the device's memory: MAX_HEADER_LIST_SIZE 16 KB (Go: 10 MB), request bodies ≤ 60 KB, early payload
    ≤ 4 KB.
  - Different because there's no gzip here: no `accept-encoding: gzip`, so the server sends identity.
- **The capability version** is `TSNET_CAPVER` (`tailcfg.h`), sent everywhere the official client sends
  `CurrentCapabilityVersion`: `/key?v=`, the Noise prologue, `RegisterRequest.Version`, `MapRequest.Version`.
  - It tells the server what the client implements, so it follows what tsnet does, not Go's current version (149).
  - It is **131**, which Tailscale's control server accepts.
  - Promises at or below 131 that tsnet doesn't keep yet: PingRequest's
    disco/TSMP/ICMP/peerapi pings (12, 31), c2n requests (45–128), peer-relay disco messages (120, 121), and seamless
    key renewal (126).
- `src/tailcfg.h`: key text forms (`nodekey:`, `discokey:`, `mkey:`, `nlpub:`), netip addresses, prefixes
  and addr:ports. It also has the requests as JSON, filled as `doLogin` and `sendMapRequest` fill them: Go's always
  written fields (zero `OldNodeKey`, zero `Expiry`, null `NodeKeySignature`) and the Hostinfo an embedded node fills, including
  the required `BackendLogID`. `NLKey` is optional: it is an Ed25519 key, which mbedTLS 3.6 doesn't implement, so the
  client brings it from a vetted library. headscale and Tailscale's server both register without it (both
  tested). It reads RegisterResponse too.
- `src/mapresp.h`: a MapResponse decoded into C, the fields `mapSession` uses.
  - Nodes, normalised as `upgradeNode` does.
  - Every delta: Peers, PeersChanged, PeersRemoved, PeersChangedPatch with which fields came, OnlineChange and
    PeerSeenChange.
  - The DERP map: nil regions dropped, and "absent" kept distinct from "empty" for the merge.
  - The ping request and the control time.
  - The packet filters, the self node's CapMap and the dial plan are kept as raw JSON for the modules that read them.
  - A malformed key, address or time fails the message, as `json.Unmarshal` would. cJSON's tree is freed before
    returning.
- `src/mapmsg.h`: the map response's messages, from `readMapResponseMessage` and `decodeMsg`.
  - Framing: a little-endian uint32 size, then the message.
  - zstd: the client asks for `Compress: "zstd"` as the official client always does. Every frame in a message is
    decoded with the vendored libzstd (`third_party/zstd`, 1.5.7, unmodified).
  - The keep-alive fast path: the compressed `{"KeepAlive":true}`, once seen, is recognised without decoding.
  - Limits, smaller than Go's for the device: 2 MB a message on the wire, checked before allocating (Go:
    256 MB, `TSNET_MAPMSG_WIRE_MAX`); 4 MB decoded (Go: 1 GB, `TSNET_MAPMSG_DECODED_MAX`); a zstd window of at most
    4 MB (`TSNET_MAPMSG_WINDOW_LOG`). Tailscale's `zstdframe`, and headscale (seen), write single-segment frames, whose
    window is the message itself. A real netmap is about 1.5 KB of JSON a peer, so 4 MB holds about 2,500 peers. A
    message over a limit ends the poll with one log line that names the constant, and the client polls again with a
    fresh session.
  - Memory: the decoder context and, while a message decodes, its window and output, all `malloc`'d (in PSRAM on the
    device: `tsnet_malloc` prefers it). A message buffer that grew past `TSNET_MAPMSG_KEEP` (64 KB) is freed once the message is
    handled, so one big netmap doesn't hold up to 6 MB for the rest of the poll.
  - `src/json.h` also refuses JSON with more than `TSNET_JSON_MAX_VALUES` (200,000) values, because cJSON allocates a
    node (about 50 to 60 bytes) for each one: 2 MB of `[1,1,...` would make a 60 MB tree. That is about 12 MB at most.
- `src/netmap.h`: the netmap across one map poll, `map.go`'s `mapSession`. Each poll starts a new session, as
  each `sendMapRequest` makes a new `mapSession`.
  - Peers: a full `Peers` list replaces them all, and nothing else touches peers that message. Otherwise, in order:
    PeersRemoved, PeersChanged, PeerSeenChange ("seen" records the time given), OnlineChange, then PeersChangedPatch,
    field by field.
  - Peer cap: at most `TSNET_NETMAP_PEERS_MAX` (1,024, under 1 MB; a home tailnet is a few hundred nodes). A
    `Peers` or `PeersChanged` list is decoded for its first 1,024 nodes only. A new peer that would pass the cap is not
    kept, however it arrives (a full list or `PeersChanged` growth), and one log line gives the count. Known peers
    still update and a removal makes room. The poll goes on.
  - The rest: the self node; the DERP map's merge (absent Regions or HomeParams keep the old ones, and HomeParams
    without RegionScore keeps the old scores); the named packet filters (`PacketFilter` is "base", a `"*": null`
    clears them, a null list deletes one, `[]` stays an empty list); the domain; the control time.
  - The first non-keep-alive message must carry Node, or `apply` fails ("initial MapResponse lacked node").
  - Each apply returns what changed. Lookups go by node ID (peers kept sorted by ID, as `sortedPeers`), node key or
    address, and the filter rules come out as one JSON array in name order.
- `src/platform.h` storage: `tsnet_store_get/set`, tsnet's own small values. On the device they live in the NVS
  namespace `tsnet`; on the host, in files in `$TSNET_STATE_DIR`, written to a temporary file and renamed so a crash
  leaves the old value or the new one.
  - On the host, the state directory must be the user's own, mode 0700 and not a symlink, or the store refuses it. Files
    are opened with `O_NOFOLLOW`; the temporary file is always new (`O_EXCL`, 0600); the directory is synced after the
    rename. `tsnet-state/`, the tools' default directory, is gitignored.
  - On the device, NVS holds the keys in plaintext. Anyone with the flash can read them, and the node key is the node's
    identity on the tailnet, so a device that can be taken away needs flash encryption and NVS encryption turned on.
  - Key copies are wiped after use: the register body, h2's request bodies and output buffer, a part-loaded identity.

  tsnet reads no other namespace.
- `src/identity.h`: the keys a node keeps.
  - The machine key, made at first start and kept.
  - The node key and the old node key, changed only as `doLogin` changes them: a key is tried for a register (a new one
    when regenerating or when there is none, the current one becoming the old one), and kept only once the register
    succeeds.
  - The Ed25519 NL key (`persist.NetworkLockKey`) from the vendored Monocypher (`third_party/monocypher`).
  - The log ID, with `BackendLogID` its public ID, the hex SHA-256 (`logid.PrivateID.Public`).
  - The stable node ID.
  - A stored key that can't be read stops the load, as tailscaled won't start on a bad machine key, rather than
    quietly becoming a new node.
- `src/policy.h`: the control client's decisions, pure and host-tested.
  - `util/backoff`: `min(n²·10 ms, 30 s)` times a random 0.5–1.5, applied after the cap.
  - The rate limits: 429, or 503 with `Retry-After` (seconds or an HTTP date), else 5–10 s, at most 5 minutes.
  - What a register's response means (`doLogin`'s order: the rate limit, the status, `Error`, a new node key for
    `NodeKeyExpired` or `NodeKeySignature`, `AuthURL`), and what the end of a map poll means (404 is `ErrNodeRemoved`).
- `src/client.h`: the control client, `controlclient`'s Auto and Direct as one event loop on one connection.
  - **Login:** the server's key once, then a register with the stored node key. The auth key goes only with a first
    register or a new node key, so a registered node's restart doesn't resend a key built into its image. A server
    that wants a new node key gets one at once; a refusal or an `AuthURL` is NEEDS_AUTH and the login backs off.
  - **The map poll:** streaming, zstd, each message through `mapmsg` and `netmap` to the app's `on_netmap`. A full
    netmap resets the map backoff. The 120 s watchdog is reset when the 200 arrives and by each message.
  - **When a poll ends** (the watchdog, an error, the server closing it), the stream is reset and a new poll starts
    after the map backoff, **on the same connection**: the official client does exactly that, measured on the
    harness. A 404 is
    NODE_REMOVED, and the polls go on.
  - **A netmap whose self node has expired** is NEEDS_AUTH ("node key expired"), as ipnlocal's `keyExpired` is
    NeedsLogin, and the polls go on. headscale answers a deleted node this way (a placeholder node expired in
    1970), and tailscaled then polls about every 10 ms, each netmap resetting the backoff. tsnet does the same.
  - **The state stays RUNNING across polls**, as tailscaled's backend stays Running. `tsnet_client_in_map_poll` says
    whether a poll is open.
  - **TCP keep-alive** is set as Go's dialer sets it (the platform's connect: idle 30 s, interval 15 s, 9 probes;
    lwIP has `LWIP_TCP_KEEPALIVE`). A connection that fails is dialed again.
  - `PingRequest` with no type and a Noise URL gets its HEAD.
  - **What magicsock reports**: the disco key, the endpoints (with their types) and NetInfo go in every
    MapRequest, and NetInfo in the register's Hostinfo too (`hostInfoLocked`). A change sends a **lite map update**
    once logged in (`updateRoutine`, `SendUpdate`: OmitPeers, no stream, the body dropped), the same `informed` rule as
    Go's (a change during one sends another), Retry-After on 429 or 503, and the 30 s backoff on other errors.
  - **Not yet:**
    - the other ping types and c2n;
    - the Tailnet Lock re-sign, and waiting on an `AuthURL`;
    - the RST_STREAM+PING Go sends when it cancels a stream that has read nothing;
    - pausing on a link change: tailscaled pauses the control client while no interface is up and resumes it when
      one is (`linkChange`, `shouldPauseControlClientLocked`). An app on wifi needs this.
  - **Untested:** a path that dies without a reset. The watchdog (120 s) fires before keep-alive (about 165 s) can,
    and the re-poll puts data in flight, so when the connection closes and is dialed again depends on the TCP
    stack's retransmission limits.
- `src/derp.h`: DERP's frame protocol, the client side of `derp/derp.go` and `derp_client.go`. Pure: bytes in,
  messages out, and writers for the frames to send.
  - **The handshake:** the first frame must be the server's key (the magic, at most 1 KB), then the client sends its
    key and a NaCl box of `{"version":2,"CanAckPings":true}` sealed to the server's key (what magicsock sets).
    ServerInfo is opened from the server's key, and a box or JSON that fails ends the connection, as in Go.
  - **Every frame Recv handles** is parsed as Recv parses it (packets, keep-alives, peer gone and present, ping, pong,
    health, restarting), and a short one is dropped as Recv drops it. A frame over 1 MB ends the connection.
  - **Different, for memory:** a frame over 4 KB (`TSNET_DERP_BUF`) is skipped, where Go allocates for it. WireGuard
    and disco packets are under 1.5 KB.
  - **Not yet:** holding sends to the server's token bucket (ServerInfo's `TokenBucketBytesPerSecond`, which Go's
    `setSendRateLimiter` enforces). The values are reported.
- `src/derphttp.h`: one connection to one DERP region, `derphttp_client.go`'s connect as a non-blocking step.
  - **The connect:** each of the region's nodes in order with 1.5 s to dial (STUN-only nodes skipped), the node's IPv4
    when set, else its name. Then TLS to the node's name with the certificate checked (`InsecureForTests` skips the
    check), `GET /derp` with `Upgrade: DERP` (and `Ideal-Node` when it isn't the first node), a 101, and `derp.h`'s
    handshake. All of it has 10 s. The DERP map's names come from the server, so a name with a character a host name
    can't have is refused before it goes into a header.
  - **Once up:** packets, pings and NotePreferred are queued (8 KB; a packet that doesn't fit is dropped, as magicsock
    drops one when a region's queue is full), a server ping gets its pong, and 120 s with no read fails the connection.
    A failed connection stays failed: its owner makes a new one.
  - Plain HTTP only with `use_http`, Go's `TS_DEBUG_USE_DERP_HTTP`, which the harness uses.
  - `latency_check` is netcheck's `measureHTTPSLatency`: TLS always (`DialRegionTLS`), `GET
    /derp/latency-check`, and the time from the request to a 2xx response's head.
  - **Not yet:** fast start (the TLS 1.3 meta certificate: a round trip saved), a node's `CertName` (such a node is
    skipped), IPv6, proxies and websockets.
  - Frames queued while connecting go once the handshake is done, ClientInfo first (magicsock's writes wait in the
    region's `writeCh` while `Send` connects).
- `src/derpmgr.h`: magicsock's DERP connections (`wgengine/magicsock/derp.go`), one `derphttp` per region.
  - **Home:** connected while it is home and told so (`NotePreferred`). magicsock sets it from each netcheck report
   ; with no preferred region it is `pickDERPFallback`'s: the current home, else a random region of the map.
  - **A peer's region** opens when a packet goes there (`derpWriteChanForRegion`). A reply to a peer heard over
    another region goes back that way (`derpRoute`), which PeerGone and a broken connection remove.
  - **A broken connection** is dialed again after `runDerpReader`'s backoff (n² × 10 ms, at most 5 s, reset by any
    message). A packet sent while the backoff is running is dropped, not queued. The backoff window must pass before a
    reconnect dials. A server that completes the handshake (sends a message) resets the backoff, so this bound
    applies to servers that drop before any frame. **A non-home connection** closes after more than 60 s unwritten,
    checked every 15 s (`cleanStaleDerp`).
  - **A DERP map** that redefines or drops a region closes its connection, and a home that went is cleared until the
    ReSTUN that follows sets one (`setDERPMap`). No map means no DERP.
  - At most 8 regions at once and 64 peer routes (the oldest route is forgotten). The timing rules are in `policy.h`.
  - **Not yet:** closing connections on a link change (`maybeCloseDERPsOnRebind`) and the health tracker.
    magicsock owns it; disco sends through it.
- `src/stun.h`: `net/stun/stun.go`. The binding request (SOFTWARE "tailnode", FINGERPRINT), `ParseResponse`
  (XOR-MAPPED-ADDRESS, its 0x8020 variant, MAPPED-ADDRESS as the fallback, trailing bytes trimmed), `Is`,
  `ParseBindingRequest`, and `Response` for tests. Pure; an address is 16 bytes, IPv4 as `::ffff:a.b.c.d`.
- `src/platform.h` UDP: a non-blocking socket bound to a port (`tsnet_udp_open`), `tsnet_udp_send` (a full
  buffer drops the datagram), `tsnet_udp_recv` with the sender, and `tsnet_resolve4` (an IPv4 literal skips the
  resolver). IPv4 only for now; the same BSD calls on the host and lwIP. `tsnet_now_us()` is the clock in
  microseconds, for latencies. `tsnet_ifaddrs` lists the interfaces' addresses: getifaddrs on the host,
  esp_netif walked in lwIP's context on the device (an IPv6 address there counts as /64: esp_netif doesn't say).
- `src/ncplan.h`: netcheck's decisions, pure. The probe plan (`makeProbePlan`): a full report probes every
  region that can be home, 3 tries 100 ms apart; an incremental one the 3 fastest regions (2 tries for the fastest
  two) and the home (4 tries, so one slow sample can't move it), with delays from the last latency. The history and
  preferred DERP (`addReportHistoryAndSetPreferredDERP`): the best latency per region over 5 min 5 s, scaled by
  HomeParams' RegionScore; the old home kept unless the new one is 10 ms and a third better; the forced region when it
  answered or was heard; the old home kept when there's no data but DERP was heard within 2 minutes. IPv4 only.
- `src/netcheck.h`: `GetReport` as a non-blocking step. STUN probes on the plan over the caller's UDP socket
  (the caller hands back the STUN packets that arrive on it), the latency, the address the servers saw and whether
  it varies by server, the first answer in a region stopping its other probes, the rest stopped once 3 regions have
  answered (after the slowest latency, twice that in a full report), STUN over after 3 s and the report after 5 s.
  With no STUN answer (UDP blocked), each region still without a latency gets one over HTTPS: `derphttp.h`'s latency
  check, verified TLS and `GET /derp/latency-check`, at most 4 at once (Go starts them all). A full report comes
  first, every 5 minutes and when asked for.
  - **Not here:** ICMP, IPv6, port mapping (UPnP, NAT-PMP, PCP) and captive portal detection. A node's name is
    resolved when its probe goes (blocking DNS; Tailscale's map gives IPv4 literals, which skip it).
- `src/magicsock.h`: the start of `wgengine/magicsock`'s `Conn`, with disco, endpoints and WireGuard. It owns the node's UDP socket, the DERP manager and netcheck.
  - **ReSTUN** runs a report (`updateNetInfo`), and its preferred region becomes the DERP home (`maybeSetNearestDERP`:
    while out of contact with control, a home already set stays). A ReSTUN asked for during a report runs after it.
  - **When:** on a DERP map change, when the first peer arrives, and every 20 to 26 s while there are peers and
    traffic (`periodicReSTUN`; `shouldDoPeriodicReSTUNLocked` stops it after 45 s with no packet sent or received,
    counted from magicsock's start).
  - A STUN binding packet on the socket goes to netcheck (`packetLooksLike`), a disco packet (over UDP or DERP) to
    `handleDiscoMessage`, and any other to `on_packet`: WireGuard's, with its source (an address and
    port over UDP, a node key over DERP). WireGuard over DERP from a node key no peer has is dropped
    (`processDERPReadResult`).
  - NetInfo (tailcfg's, with the latencies) is reported when it changes as `BasicallyEqual` sees it, for the control
    client.
  - **Endpoints**: after each report, `selfeps.h`'s `determineEndpoints`; reported when the set changes
    (`setEndpoints`, `epFunc`), but not before there's a STUN endpoint or a DERP map. The log gives their count and
    types, never the addresses (this node's public and LAN ones).
  - **CallMeMaybe out** (`enqueueCallMeMaybe`): when a peer's discovery wants one and the peer has a DERP home, this
    node's endpoints go to it over DERP. Endpoints older than 27 s ReSTUN first ("refresh-for-peering"), and it goes
    when that report is in (`onEndpointRefreshed`).
  - `GetLastDERPActivity` is the DERP manager's last frame per region, recorded at most every 5 s as health does.
  - **Peers** come from the netmap's nodes (`updateFromNode`): node key, disco key, home DERP and endpoints.
    A peer keeps its paths across netmaps; a new disco key resets them (`changedActiveDiscoLocked`).
  - **Disco in:** a packet from a disco key no peer has is dropped, and so is one that doesn't open. A Ping gets a
    Pong the way it came (over DERP, to the node that sent it); a ping from a new UDP address adds it as a candidate.
    A Pong goes to the peers with that disco key until one sent the ping. A CallMeMaybe counts only over DERP, from
    the peer whose netmap disco key sealed it.
  - **Pinging** (`tsnet_magicsock_ping`, `Conn.Ping`'s disco ping): over the peer's DERP home while there's
    no trusted path, and to the trusted path alone or to every endpoint; the first pong goes to `on_ping`. A peer's
    disco key change is logged.
  - **Sending** (`tsnet_magicsock_send`, `endpoint.send`, what WireGuard calls): see `endpoint.h`. With no
    UDP path and no home DERP, it goes over the region the peer last reached us over (`fallbackDERPRegionForPeer`).
  - **WireGuard over it**: `wgdev`'s messages go out with `tsnet_magicsock_send`, and `on_packet` hands what
    comes in to `tsnet_wgdev_receive`. WireGuard finds a transport packet's peer by its receiver index and an
    initiation's by its static key, so Go's map from source address to peer (`setNodeKeyForEpAddr`, which feeds
    wireguard-go's endpoints and wgengine's activity) isn't needed for routing, and isn't kept. A node with no trusted
    path answers over DERP, as Go's does. A cookie reply goes back to its source (`tsnet_magicsock_reply`, `Conn.Send`):
    to a node key as any send goes, to a UDP address straight from the socket (`lazyEndpoint`).
  - Each peer is about 2.9 KB, measured on the host (mostly `endpoint.h`'s tables).
- `src/selfeps.h`: this node's own endpoints, pure (`determineEndpoints`, `endpoint_tracker.go`,
  `netmon.LocalAddresses`).
  - **STUN:** the report's `GetGlobalAddrs` (the fastest server's view, then any other seen more than once), and
    behind a NAT whose mapping varies with a fixed UDP port, that address with the fixed port (STUN4LocalPort).
  - **The tracker** keeps a STUN endpoint advertised 5 min 10 s after a report last saw it, at most 6 per address.
    It has 24 slots (Go's map grows): when they're full, the oldest goes.
  - **Local:** the interfaces' addresses on the bound port. Up interfaces only, not ZeroTier's or NetBird's, not
    Tailscale's own addresses, no IPv6 link-local, at most 2 IPv6 per subnet. IPv4 link-local and IPv6 ULA only when
    there's nothing else, loopback only when there's nothing at all.
  - **Not here:** port mapping, cloud metadata addresses, static endpoints and IPv6 STUN. One divergence: a local
    endpoint the tracker already gave isn't added twice (Go's can be).
- `src/endpoint.h`: a peer's paths, pure (`wgengine/magicsock/endpoint.go` without the sockets).
  - **Endpoints:** the netmap's, ones the peer pinged from (gone 45 s after its last ping), and a CallMeMaybe's
    (replaced by the next CallMeMaybe).
  - **CallMeMaybe limits** (not in Go): Go drops only IPv6 link-local targets, so any peer could aim our pings
    at loopback, multicast, broadcast or 169.254.169.254. tsnet also drops unspecified, loopback, multicast,
    broadcast (255.255.255.255), IPv4 and IPv6 link-local and port 0 targets, and keeps LAN and public ones. It
    handles one CallMeMaybe per peer per 2 s (`TSNET_CMM_MIN_INTERVAL_US`) and ignores the rest. A real peer sends
    one at most every 3 s. The subnet-directed broadcast address isn't dropped: the endpoint code doesn't know the
    local subnet.
  - **The best address** is a UDP endpoint that answered a ping, trusted for 6.5 s after each pong. A pong from a
    better address (`betterAddr`: latency, then loopback, link-local, private and IPv6 preferences, with 1%
    stickiness), or from any while the best is untrusted, replaces it. A ping to an untrusted best that times out
    (5 s) clears it.
  - **Sending:** to the trusted best alone; else to it (if any) and the peer's DERP, with a discovery ping to each
    endpoint not pinged in the last 5 s. A send starts the heartbeat: every 3 s a ping to the best, and a full round
    when `wantFullPingLocked` says so (no trusted path, or a minute passed and the path is slower than 5 ms), until
    45 s pass without a send.
  - **Not here:** UDP relay (Geneve) paths, peer MTU probing (off by default in Go), WireGuard-only peers, UDP
    lifetime probes and the pong history (Go reads it only for WireGuard-only peers and status).
  - **Caps where Go grows:** 16 endpoints per peer (Go prunes at 100) and 32 pings in flight (the oldest is
    forgotten). When the 16 are full, a new ping-learned candidate waits until one expires, but a netmap or
    CallMeMaybe endpoint evicts the oldest candidate, so pings from spoofed addresses can't keep the real
    endpoints out. Netmap and CallMeMaybe endpoints are never evicted.
  - **Ping replay** (not in Go): the last 32 ping txids of each peer are remembered, from any address. A
    repeated txid draws no pong and adds no candidate. Go remembers one txid per endpoint, so a captured ping replayed
    from alternating addresses drew a pong each time. Pings over DERP don't go through this: a DERP replay can only
    make the node answer the peer that sent it.
- `src/disco.h`: `disco/disco.go`, pure. Ping (TxID, node key, padding), Pong (TxID, the source address) and
  CallMeMaybe (endpoints), parsed and marshalled as Go does (a zero node key left out, trailing zeros read as padding,
  a CallMeMaybe of another version or a partial endpoint read as none); the relay messages (4 to 9) recognised, not
  decoded. The packet: the magic, the sender's disco key, a nonce, and a NaCl box with the two disco keys' shared key.
  At most 64 endpoints of a CallMeMaybe are kept (Go keeps all; a 1.5 KB packet holds 83). The node's disco key
  (`key.NewDisco`) is magicsock's: a new clamped X25519 key each start, never stored, as tailscaled does.
- `src/wg.h`: WireGuard's messages, pure, from Tailscale's wireguard-go fork at the commit v1.104.1 pins
  (417aef361226): `noise-protocol.go`, `noise-helpers.go`, `cookie.go`, `replay`, `ratelimiter` and `tai64n`.
  - **The handshake** (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, no preshared key as Tailscale sets none): the initiation
    (148 bytes) and response (92) in both roles, and the transport keys. Consuming an initiation is two calls, as the
    peer lookup sits between decrypting the static key and the timestamp; a replayed timestamp and an initiation under
    50 ms after the last are refused.
  - **mac1 and mac2:** what every handshake message carries, the checks, and the cookie reply (XChaCha20-Poly1305 from
    Monocypher). The sender index sits outside the AEAD, covered by mac1 alone, so mac1 is checked first.
  - **The rate limiter**, for handshakes under load: 20 a second per source, 5 in a burst, as wireguard-go's.
    A UDP source counts by its address alone. **Different, for memory:** a table of 16 sources, not a map. With all 16
    active, a new source is refused, so a flood from many sources can't refill its own buckets.
  - **Transport:** the 16-byte header, ChaCha20-Poly1305 with the counter as the nonce, padding to 16 (Go also caps the
    padding at the MTU; that comes with the IP side). The replay filter is RFC 6479's, an 8128-message window.
  - **Not here:** the index table, keypair rotation, the timers and queues.
- `src/wgdev.h`: WireGuard's device and peers (`peer.go`, `timers.go`, `send.go`, `receive.go`), one state
  machine with no threads. Two callbacks carry WireGuard messages out (to magicsock) and decrypted IP packets in
  (to the IP side).
  - **Peers** by static key, or lazy: made by an initiation the lookup callback accepts, removed 540 s after their last
    session (`deleteOnIdle`).
  - **Keypairs** current, previous and next, rotated as `BeginSymmetricSession` and `ReceivedWithKeypair` do: a
    responder's is "next" until the first data packet confirms it, and a packet under the previous one still opens
    after a rekey.
  - **Sending** stages the packet and sends what's staged, or starts a handshake (at most one every 5 s) when there's no
    usable keypair. **The timers:** a retransmit after 5 s plus jitter, giving up after 20 initiations (the staged
    packets dropped); a keepalive 10 s after data arrived unanswered; a new handshake 15 s after data went unanswered;
    the keys zeroed after 540 s. The initiator rekeys at 120 s, and once more at 165 s on receiving.
  - **The wall clock** dates an initiation (TAI64N). A peer refuses one not newer than the last it took from us.
  - **Different, for memory:** 16 packets staged per peer (wireguard-go: 128), each malloc'd, the oldest dropped. A
    peer is 4,080 bytes, measured on the host, mostly the three keypairs' replay rings (1,128 bytes each).
  - **Under load**: a handshake message must carry a mac2 from our cookie for its source, or it gets a cookie
    reply (back to that node key or UDP address) and no X25519. Then the rate limiter applies. **Different:**
    wireguard-go is under load with 128 handshakes queued, and tsnet has no queue. It is under load at 8 handshake
    messages in a second instead, and stays under load 1 s after, as Go does. A cookie for a UDP address doesn't follow
    a peer to a new path (Go keys a known peer's by one fixed address).
  - **Not here:** persistent keepalive (Tailscale sets none). AllowedIPs is the tun's (below). Padding goes to a multiple of 16, never past the TUN MTU of 1280 (`tsnet_wg_padding`).
- `src/allowedips.h`: AllowedIPs (`allowedips.go`), each peer's prefixes from the netmap. The longest match
  routes an outgoing packet to its peer. A decrypted packet's source must have its peer as its longest match
  (`Lookup(src) != peer` drops), so a peer with a wide prefix can't send as an address another peer holds.
  - **Different, for size:** a flat table searched in full, not a trie. A peer has a handful of prefixes.
- `src/tun.h`: the tunnel's IP side (`net/tstun`'s wrapper, `RoutineReadFromTUN`,
  `RoutineSequentialReceiver`). An lwIP netif on the node's tailnet IPv4 address, MTU 1280, which lwIP routes the
  100.64.0.0/10 subnet to. It is never the default netif.
  - **In:** a decrypted packet whose source AllowedIPs refuses is dropped. The rest are queued and fed to the netif's
    input in `tsnet_tun_step`, after wgdev returns.
  - **Out:** lwIP's output is copied, queued, and routed by AllowedIPs in `tsnet_tun_step`. A packet for an address no
    peer has is dropped. The queues mean that lwIP and wgdev never call into each other.
  - **Threads:** on the device, lwIP runs in its tcpip thread, and the netif's input is `tcpip_input`. On the
    host, lwIP is NO_SYS, and the input is `ip_input`. The netif and the out queue are touched only in lwIP's context,
    through `tsnet_ip_exec`. lwIP's output wakes tsnet's loop through `tsnet_tun_fd`. It runs on an ESP32-P4.
  - **The netif's `state` stays NULL.** ESP-IDF's esp_netif treats every netif's `state` as its own `esp_netif_t`
    (without `LWIP_ESP_NETIF_DATA`), and skips a NULL one. A tun pointer there was written through on the device's
    first run, a store fault at the first address. The tun finds itself from the embedded netif (`tun_of`).
  - **The packet filter:** after AllowedIPs, a decrypted packet goes through `src/filter.h`. TSMP never
    reaches lwIP: a TSMP ping (`tailscale ping --tsmp`) gets its pong whatever the rules say, as in tstun, and the rest
    goes nowhere. A refused TCP SYN gets tstun's TSMP reject back (`'!'`, reason `'A'`), so the sender's tailscaled
    logs why. lwIP's output goes through the filter in `tsnet_tun_step`, which records UDP flows.
  - **Not here yet:** IPv6.
- `src/filter.h`: the packet filter (`wgengine/filter` at v1.104.1), for IPv4.
  - **The rules** come from the netmap's packet filter JSON (`MatchesFromFilterRules`, then the IPv4 half
    `matchesFamily` keeps). An entry that doesn't parse is skipped. `SrcBits` or `DstPorts[].Bits` leave no rules, as
    in Go. **Local** addresses are the node's own.
  - **In** (`RunIn`): `pre` drops junk, multicast and link-local, and passes later fragments. A packet for an address
    that isn't local is dropped. ICMP replies and errors pass, and other ICMP passes when any rule reaches the address.
    TCP that isn't a SYN passes, and a SYN needs a rule. UDP needs a rule or a flow this node started. Before the
    first rules, nothing gets in (`NewAllowNone`).
  - **Out** (`RunOut`): drops junk and records each UDP flow for its replies.
  - **Different, for memory:** the flow cache is Go's LRU of 512 flows, kept across rule updates, but grown as it's
    used: 20 bytes a flow, 10 KB when full.
  - **Jailed peers** (`IsJailed`) get Go's jailed filter: no rule matches, with a flow cache of its own, so they can't
    open a connection to the node. A refused SYN from one gets a reject with reason `'S'` (shields up).
  - **Not here:** peer capabilities (`cap:` sources never match, so those rules drop).
- `src/platform.h` IP stack: `tsnet_ip_exec` runs a function in lwIP's context. The device uses
  `esp_netif_tcpip_exec`, since the apps' lwIP has no core locking. The host calls the function directly.
  `tsnet_wake_*` wakes the loop from another thread: an eventfd on the device, a non-blocking pipe on the host.
- `src/platform.h` memory: the core allocates with `tsnet_malloc`, `tsnet_calloc` and `tsnet_realloc`, and
  frees with `free()`. On the device they prefer PSRAM. ESP-IDF serves any allocation under 16 KB from internal RAM
  otherwise, and on the device's first run tsnet's state took it down to 4.7 KB free, until the wifi driver couldn't
  get a receive buffer and asserted. With PSRAM, 154 KB stays free.
- `src/server.h`: a tailnet node in one call, what Go's `tsnet.Server` sets up.
  - **What it runs:** the control client, magicsock, WireGuard and the tun with its filter, in one event loop
    (`tsnet_server_poll`, `tsnet_server_step`).
  - **Each netmap:** sets the WireGuard peers, their routes, the node's address and the filter's rules.
  - **The disco key** is made before the client starts, so its first MapRequest carries it
    (`Options.DiscoPublicKey`). magicsock takes it as `disco_priv`.
  - **What the app does:** sets the wall clock first (TLS dates, WireGuard's timestamps), and sizes the task's stack
    for the measured peaks. `magicsock_run` is its host caller, so the harness runs what the device runs.
  - **Names:** `tsnet_netmap_peer_by_name` finds a peer by MagicDNS short name or FQDN, as `microlink_resolve` did.
  - **WireGuard peers:** each netmap peer that isn't expired, with only its own Tailscale addresses as AllowedIPs: no
    exit node's /0, no subnet routes, as Go configures a node that uses neither. A peer that expires or leaves the
    netmap is removed and its keys wiped.
  - **Not here:** lazy WireGuard peers (Go configures them lazily and trims idle ones).
- `src/json.h` (the security review): every JSON tsnet parses goes through `tsnet_json_parse`, which refuses nesting
  deeper than 32 before cJSON recurses into it. On the device cJSON costs 96 B of stack a level to parse and 192 B to
  print, and its own limit (1000) is past tsnet's 24 KB task stack.

## Testing

`test/test.sh` builds the core with the host back end and runs the tests under ASan and UBSan. A UBSan report stops
the test (`-fno-sanitize-recover`); glibc's `nonnull` makes `memcpy(p, NULL, 0)` one, which macOS doesn't report, so
guard a copy that can be empty. The core is compiled once, in parallel, and each test links it. It links mbedTLS, cJSON and lwIP: ESP-IDF's own copies when `IDF_PATH` is set, else the pinned releases
`tools/fetch_deps.sh` downloads and checks (sha256), into `$TSNET_HOST_BUILD` (default `~/.cache/tailscale-embedded`).
lwIP is built with NO_SYS and the options in `test/lwip/lwipopts.h`. lwIP keeps one stack a process, so only one node in a test has one.

The vectors in `test/crypto_test.c` are RFC 7748 (X25519, including the 1,000-iteration one), RFC 8439 section 2.8.2
(ChaCha20-Poly1305) and RFC 7693 appendix B (BLAKE2s), each checked against Python's `cryptography` (OpenSSL); the keyed
BLAKE2s, HMAC-BLAKE2s and Noise-HKDF values are CPython `hashlib`'s.

`test/noise_test.c` runs the handshake against a responder written separately from controlbase's server side
(`responder.h`); `controlhttp_test.c` dials that responder in a forked loopback server (a record each way with the
bytes after the head kept, the server's error frame, a 200, the wrong `Upgrade`, both ports refused without waiting
500 ms, and the timeout, plus 2 MB through `write_some` while the server reads late, so records queue and still arrive
whole and in order); `hpack_test.c` decodes RFC 7541 Appendix C and blocks from Python's `hpack` 4.1.0
(Huffman on every byte value, eviction, size updates down to 0 and back, never-indexed), written to
`test/hpack_vectors.h` by `tools/hpack_vectors.py` (`uv run --with hpack==4.1.0`), and every error RFC 7541 names,
plus 200,000 random blocks and every vector with each byte changed; `h2_test.c` plays a scripted server (a response
with 1xx, padding, priority and CONTINUATION fed at every split point, the early payload, flow control both ways, PING,
RST_STREAM, GOAWAY, a cancelled stream whose block still feeds the table, stream errors and 21 connection errors, and
garbage); `http1_test.c` feeds responses split at every point; `controlkey_test.c` parses the real `/key` response and its
broken forms; `tailcfg_test.c` reads the requests back as JSON, decodes headscale's real register response and map
messages (`test/fixtures/headscale/`), hand-built deltas and patches, malformed fields, and the real message cut short
and byte-flipped; `mapmsg_test.c` splits messages at every byte and decodes `test/fixtures/zstd/` (headscale's own
frames, the reference CLI's from a real message, a keep-alive repeated, two frames in a message, a bomb past the
decoded cap, a 32 MB window, truncation, a flipped byte, and garbage; and, built in the test, a bomb of a few dozen
bytes just past the decoded cap, one at the cap, an 8 MB window and a big message followed by a small one), written by `tools/zstd_fixtures.sh` from the
reference `zstd` CLI built from the same release; `netmap_test.c` applies sequences (headscale's real first message,
then every delta, patch, DERP merge and filter case) and checks the state after each, plus 2,000 random adds and
removes against the expected set, and the peer cap (a full list, then growth through `PeersChanged`); `identity_test.c` checks the keys across restarts in a temporary state directory, the
node-key steps of `doLogin`, RFC 8032's first Ed25519 vector and the log ID's SHA-256; `policy_test.c` checks the
backoff steps and cap, the rate-limit and `Retry-After` rules, and what each register and map response means;
`crypto_test.c` also checks NaCl box against PyNaCl (libsodium) at 18 lengths around the block edges, with every byte of
each box changed, written to `test/box_vectors.h` by `tools/box_vectors.py` (`uv run --with pynacl==1.5.0`);
`derp_test.c` plays the DERP server: the greeting, ServerInfo sealed to the client, ClientInfo opened as the server
opens it, every frame type fed at every split point, each short frame Recv drops, each failure that ends the
connection, and 3,000 streams with bytes changed; `derphttp_test.c` plays a DERP server on loopback over plain HTTP:
it checks the request, sends the 101 and the greeting in one write, opens ClientInfo, sends ServerInfo and a ping
(answered), and echoes a packet; a refused first node, a STUN-only node and a `CertName` node are passed over and
`Ideal-Node` names the first; a 426, a close after the greeting, no node to dial, and a host name carrying a header
all fail; a packet queued while connecting arrives after ClientInfo and NotePreferred. `derpmgr_test.c` runs the
DERP manager against two loopback DERP servers (a fork per connection, each packet answered as if its peer replied):
no map, the fallback home, a bigger map keeping the home, a peer's region opened on demand, the reply sent back over
the region the peer was heard on, the home dialed again twice after its connection breaks, a home the map lacks (set,
nothing opened), a region redefined, the home's region dropped (a new home), no map again, and a server that drops
every connection before any frame while a packet goes every few ms for 1 s: it counts 2 to 10 dials, as the backoff
allows, not one per packet. `policy_test.c` checks the 5 s backoff cap, the 60 s idle rule and the fallback.
`stun_test.c` parses Go's own response vectors (`net/stun/stun_test.go`'s nine real responses, written
to `test/stun_vectors.h` by `tools/stun_vectors.py`) with every truncation and byte change, Go's `Is` and `Response`
cases, a request matching one built with Python's zlib CRC-32, each way `ParseBindingRequest` refuses, and a request and
response between two UDP sockets on loopback. `ncplan_test.c` ports Go's own `netcheck_test.go` cases: every
`TestAddReportHistoryAndSetPreferredDERP` case, `TestRecentReportsRetainFullNetcheck`, and `TestMakeProbePlan`'s IPv4
plans, plus avoided regions and unusable IPv4 fields. `netcheck_test.c` runs reports against STUN servers on loopback
that answer after their own delays (5, 25 and 60 ms, measured as such): the fastest preferred, our address and its
count, one request to a region that answered first, an incremental report keeping the home, a NAT whose mapping varies
by server, UDP blocked (STUN gives up at 3 s, the full plan's 3 tries a region, HTTPS tried), and stray STUN messages.
`magicsock_test.c` runs magicsock against two loopback STUN servers: the map's report setting the faster region as
home, a ReSTUN during a report running after it, NetInfo reported only on a change, the home kept while out of contact
with control and moved once back, and the first peer (not the second) starting a report. `disco_test.c` checks Go's
own `TestMarshalAndParse` vectors for Ping, Pong and CallMeMaybe both ways, packets sealed by one side and opened by
the other, every truncation and changed byte, and 20,000 random messages. `endpoint_test.c` checks Go's own cases for
`betterAddr`, `discoPingTimeout` and `handlePongConnLocked` (not the Geneve ones), then the trust window, what starts
pings, the heartbeat, the endpoints' lifetimes and the caps. `magicsock_test.c` also runs three magicsocks on
loopback: a send finds the direct path, the heartbeat keeps it trusted past 6.5 s, a node whose disco key the other
doesn't know gets no pong, and a restarted node (a new disco key and port) is found again; and the first report's
endpoints (one STUN, the interfaces') reported once. `selfeps_test.c` checks Go's own `TestEndpointTracker`,
`TestEndpointTrackerMaxNum` and `TestEndpointSetsEqual` vectors, then the local address rules, `determineEndpoints`
and the host's own interface list. `tailcfg_test.c` checks NetInfo's JSON as `updateNetInfo` fills it. `wg_test.c`
checks wireguard-go's own KDF vectors and replay cases (the Linux kernel's), then the initiation, response, keys,
transport messages and cookie reply byte for byte against an independent reference (`tools/wg_vectors.py`: the
WireGuard paper on OpenSSL, hashlib and libsodium, writing `test/wg_vectors.h`), every changed byte, a replay and a
flood, and a round trip with fresh ephemerals. `wgdev_test.c` runs two devices through a queue that can drop packets,
on a fake clock: a handshake on demand and data both ways, the responder's keypair confirmed by data, a keepalive, a
rekey at 120 s with a packet under the old keypair still opening, a keypair refused past 180 s, retransmits and giving
up after 20 initiations, a replay dropped, a lazy peer made and reaped, the staged queue's cap, and crossing handshakes.
`wgnode_test.c` joins a magicsock and a wgdev per node, as the tools do, and sends an IP packet each way through a
real handshake over a direct path on loopback; a WireGuard-shaped packet with no keypair is dropped.
`allowedips_test.c` ports wireguard-go's `TestTrieIPv4` and `TestTrieIPv6` lookups, and checks source addresses and
removing a peer. `tun_test.c` runs lwIP behind one node's tun and a bare wgdev as the other: an ICMP echo and a UDP
echo come back through a real handshake, a spoofed source is dropped, a packet for an address no peer has goes
nowhere, and lwIP's output makes the tun's wake fd readable until a step sends it. Nothing gets in before the filter's
first rules, and a SYN its rules refuse gets a TSMP reject. `filter_test.c` ports `wgengine/filter`'s IPv4 tests
(`TestFilter` in its order, `TestUDPState`, `TestPreFilter`, `TestParseIPSet`, `TestMatchesFromFilterRules`,
`TestMatchesMatchProtoAndIPsOnlyIfAllPorts`) through the rules' JSON. The node-capability row drops, as the shortcut
says. Then it checks the TSMP reject's and pong's bytes against `tsmp.go`'s layout, the flow LRU, and rules that keep
the flows. `json_test.c` checks the JSON depth limit and the map shapes the security review found (PacketFilters as an
array, duplicate DERP region IDs, numbers past int64). `fuzz_test.c` mutates valid STUN, HTTP/1, IP and WireGuard
messages through their parsers, 20,000 rounds a run (`TSNET_FUZZ_ROUNDS` for more).
**Fixtures** come from
`test/capture.c`. It registers a throwaway
node with an auth key, saves the register response and each map message, and decodes the stream through tsnet
(framing, zstd, MapResponse, the netmap session), using the capability version the client sends:
`capture http://127.0.0.1:8090 "$(harness/harness.sh key)" <dir> [""|zstd] [messages] [nlkey 0|1]`. Before
committing a capture, replace this network's addresses with documentation ones (203.0.113.0/24, 192.0.2.0/24). A
compressed frame can't be scrubbed, so only frames without addresses are committed as the server sent them.

**The live check** is `test/probe.c`, against Tailscale's real control server: `TSNET_LIVE=1
test/test.sh` (it needs the network, so CI doesn't run it). It fetches the key, dials over 80, over 443 and racing, then
runs the HTTP/2 client: the early payload checked, then three requests on one connection. Two GETs of an unknown path
come back 404 with nine header fields. An empty `POST /machine/register` comes back 400 "missing version", so the
server parsed our body. That proves the transport both ways, request bodies, and Huffman decoding against Go's real
server. It doesn't prove HPACK's dynamic table: the server never indexes its response fields (counted: no table
lookups), so only the vectors test it. Then `test/derp_probe.c` connects to Tailscale's DERP node `derp1f.tailscale.com`
with a throwaway key: TLS verified, the 101 and the greeting are required. ServerInfo is reported, not required
(on 2026-10-23 that node accepted a throwaway key and sent it; headscale's server refuses an unregistered one).
`derp_probe <host> latency` is netcheck's HTTPS latency check and `derp_probe <host> stun` one STUN request; the live
check runs both against the same node. `wrong.host.badssl.com` and
`self-signed.badssl.com` must fail at TLS. The node's name is fixed in `test.sh`, so a renamed node fails the check
until it is updated there.
`TSNET_HARNESS=1` runs the same probe against the [harness](../harness/README.md)'s headscale on `http://127.0.0.1:8090`
(`harness.sh up` first): the key over plain HTTP, and the dial on that port only, as ts2021 picks ports for an
`http://` URL on a private address (`tsnet_ts2021_ports`). `probe <server URL> [capver] [80|443]` checks another server; a host with a bad certificate
(`self-signed.badssl.com`, `wrong.host.badssl.com`) fails at the key, as it should.
With `TSNET_HARNESS=1`, `harness/scenarios.sh` then runs the control client (`test/client_run.c`) through the
harness's scenarios: join with a key, restart without one as the same node, a peer added and
deleted, an idle stream past the watchdog then a stalled server (a new poll on the same connection), the node
deleted (headscale's expired placeholder node: NEEDS_AUTH, polling on), DERP (`test/derp_run.c`: a registered
node gets ServerInfo, a pong, its own packet back, and PeerGone "not here" from Tailscale's own derpserver, which
headscale embeds), DERP regions (`test/derpmgr_run.c`: one node relays to another, a non-home region opens and
closes as idle, headscale's restart is reconnected, and the home outlives the read deadline), and netcheck
(`test/magicsock_run.c`: reports against headscale's STUN server set and connect the DERP home and repeat every 20 to
26 s, and the harness's peer's netmap then has the node's disco key, endpoints and home DERP, shown as counts by
`harness.sh seen`; with STUN dropped, the fallback home), and disco against the real tailscaled peer (`magicsock_run`'s `TSNET_PING`: the first answer over DERP, a CallMeMaybe, then a direct path to one of the peer's
endpoints; the peer's own `tailscale ping` answered directly; the peer moved to a new port and disco key, and the path
following), and WireGuard with tailscaled both ways (`TSNET_ICMP`: tsnet's echo requests answered through the
tunnel; the peer's `tailscale ping --icmp` answered by lwIP behind tsnet's tunnel, and its `tailscale nc` to port 7
echoed back; then a headscale policy with only port 22 open: the ping still answered, port 7 shut).
About 12 minutes in all.
`client_run <server URL> <seconds> [auth key]` runs the client by hand, its identity in `$TSNET_STATE_DIR`;
`derp_run`, `derpmgr_run` and `magicsock_run` take the same arguments. CI runs the harness, the probe and the
scenarios on every push and pull request ([harness](../harness/README.md)).

## On the device

Add the repository as an ESP-IDF component (`idf_component.yml`, or `EXTRA_COMPONENT_DIRS`). What a device build
needs in `sdkconfig.defaults`:

- **PSRAM for lwIP, TLS and tasks:** `CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP`, `CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC` and
  `CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM`. tsnet allocates from PSRAM first (`tsnet_malloc`); an HTTP/2
  connection is ~65 KB, a control connection ~14 KB and each DERP connection ~21 KB plus its mbedTLS buffers. In
  internal RAM these starve the wifi driver.
- **Crypto:** `CONFIG_MBEDTLS_CHACHA20_C`, `_POLY1305_C`, `_CHACHAPOLY_C`, `_HKDF_C`, `_HAVE_TIME_DATE` and
  `CONFIG_MBEDTLS_ECP_DP_CURVE25519_ENABLED`. TLS stays at 1.2: mbedTLS 3.6's TLS 1.3 client fails Tailscale's DERP
  certificate chains.
- **lwIP:** `CONFIG_LWIP_MAX_SOCKETS=16`, `CONFIG_LWIP_SO_RCVBUF`, `CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=64`, 32 KB TCP windows.
- **The clock** must be set (SNTP) before `tsnet_server_new`: TLS checks certificate dates, and peers refuse a
  WireGuard initiation dated before the last one they took from the node.
- **Certificates:** `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE` with a bundle that holds ISRG Root X1 (the full bundle does).
- **The task** that runs `tsnet_server_poll`/`step` needs a 24 KB stack. It can live in PSRAM only with
  `CONFIG_SPIRAM_XIP_FROM_PSRAM`: otherwise each NVS write turns the cache off under it. Without XIP, give it
  internal RAM.
- **Keys** live in NVS (namespace `tsnet`) in plaintext unless you turn on flash encryption and NVS encryption.
