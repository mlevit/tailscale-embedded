# tsnet's conformance harness

A headscale control server and a real `tailscaled` peer in Docker, on this machine only, for testing tsnet against
real implementations without touching the tailnet. `harness.sh` drives it:

| Command | Does |
|---|---|
| `harness.sh up` | starts headscale on `http://127.0.0.1:8090`, creates the user `tsnet`, joins the peer `tsnet-peer` (100.64.0.1) with a key it mints, waits until headscale calls it online |
| `harness.sh key` | mints a reusable, ephemeral preauth key (1 h) for a tsnet client and prints it |
| `harness.sh nodes` | headscale's node list |
| `harness.sh count NAME` / `delete NAME` | counts, or deletes, the nodes with hostname NAME (deleting is a node removed from the tailnet) |
| `harness.sh seen NAME` | what the peer's netmap (`tailscale debug netmap`) has for node NAME, as counts: `disco=1 endpoints=N derp=R` (a disco key, N endpoints, home DERP region R). The endpoints are this machine's addresses, so they're never printed. (`tailscale status`'s `Addrs` is filled for the node itself only) |
| `harness.sh probe` | `TSNET_HARNESS=1 test/test.sh`: tsnet's probe against headscale (the key over plain HTTP, the Noise dial, HTTP/2), then `scenarios.sh` |
| `harness.sh stall` / `resume` | freezes or thaws headscale (`docker pause`): a control server that stops answering mid-stream |
| `harness.sh restart` | restarts headscale |
| `harness.sh peer-port N` | restarts the peer on UDP port N, its state kept: a peer moving to a new port |
| `harness.sh peer-stop` / `peer-start` | takes the peer away, brings it back |
| `harness.sh down` | stops everything and deletes its volumes |

- **Images** are pinned by tag and digest (`compose.yaml`), each release checked first (its notes and advisories, at
  least 7 days old, scanned). Update them the same way.
- **`headscale.yaml`** is v0.29.5's `config-example.yaml` with only what the harness needs changed (it says which).
  The policy lives in headscale's database, so `headscale policy set` can change it at runtime. headscale's image has
  no shell, so `scenarios.sh` pipes the policy in on stdin (`-f /dev/stdin`). Until a policy is set, every node
  reaches every other.
- **DERP**: headscale's embedded DERP server (Tailscale's own `derpserver`), with the harness's DERP map
  (`derp.yaml`) in place of Tailscale's public one, so nothing here uses Tailscale's DERP servers. The map has one
  region (900) listing the same server twice: `127.0.0.1:8090` for tsnet on the Mac, `172.30.90.10:8080` for the peer,
  since the Mac can't reach a container's own address. Each side takes the node it can reach. headscale shuffles the
  nodes (seeded by `dns.base_domain`), so today the Mac waits out its 1.5 s dial of the second address first. Both
  sides speak plain HTTP to it (`TS_DEBUG_USE_DERP_HTTP`). It verifies clients, so only registered nodes connect.
  A second region (901) is the same server again, so a node has a region that isn't its home.
- **STUN**: headscale's embedded STUN server, its port published on the Mac's loopback (UDP `127.0.0.1:3478`) and given to the Mac-side nodes in `derp.yaml`. netcheck's tries cycle through a region's nodes, so after
  headscale's shuffle the Mac's first try may go to the peer-side node, which it can't reach.
  `docker exec tsnet-harness-peer tailscale debug derp-map` shows the map as a node gets it.
- The peer runs userspace networking (no `NET_ADMIN`, no tun). `docker exec tsnet-harness-peer tailscale status`
  shows what it sees.
- **The peer logs in by IP:** `http://172.30.90.10:8080`, headscale's fixed address on the harness network
  (`172.30.90.0/24`), not `http://headscale:8080`. For an `http://` URL on a private address, ts2021 never tries HTTPS.
  With a hostname, any reconnect within 2 minutes of the last dial is forced to port 443 (controlhttp `forceNoise443`),
  where nothing listens here, and the peer never rejoins. That happened once, after `peer-port`.
- `harness.sh` waits on the peer's own state (`tailscale status`: `BackendState` `Running`), not headscale's `online`
  flag, which lags and once hid a dead peer.
- **`scenarios.sh <client_run>`** runs tsnet's control client through eleven scenarios, about 12 minutes, and
  checks the client's log and headscale's node list:
  1. **join:** a first start with a key is RUNNING, as one node, with `tsnet-peer` in its netmap.
  2. **restart:** the same state, given the key again (as an image with the key built in is on every boot), logs in
     with the stored node key alone, as the same node.
  3. **peers:** a second client (`tsnet-other`) appears in the first one's netmap, and goes when its node is deleted.
  4. **stall:** an idle stream outlives the 120 s watchdog. Then a frozen server trips the watchdog, and after the thaw a
     new poll brings a netmap on the same connection (no second dial).
  5. **removed:** deleting the node gives NEEDS_AUTH ("node key expired"), and the polls go on. headscale answers a
     deleted node's poll with a placeholder self node expired in 1970, where Tailscale's server answers 404
     (NODE_REMOVED). tailscaled does the same with it: NeedsLogin, and a new poll about every 10 ms, since each
     netmap resets the backoff (measured on the harness peer).
  6. **derp:** `derp_run` (from the same directory as `client_run`) registers as `tsnet-derp`, connects to the DERP
     server with its node key, and gets ServerInfo, a pong to its ping, its own packet back, and PeerGone "not here"
     for a disco-shaped packet to a key nobody has (the server sends that only for disco-shaped packets).
  7. **relay:** two nodes run `derpmgr_run` (the DERP manager). A sends B five packets over DERP, and one over
     the region that isn't its home. headscale restarts, and A's connections are dialed again after the backoff. The
     non-home region, unwritten since, closes as idle (more than 60 s, checked every 15 s). A runs 170 s, so its home
     connection outlives the 120 s read deadline on the server's keep-alives.
  8. **netcheck:** `magicsock_run` reports with UDP working and a latency per region, sets the DERP home from
     the report and connects it, and with the peer in the netmap keeps reporting (at least 3 reports in 40 s: on the
     map, on the first peer, then the periodic ReSTUN every 20 to 26 s). The peer's netmap then has the node's disco
     key, its endpoints and its home DERP (`harness.sh seen`).
  9. **udp-blocked:** the same with its STUN packets dropped: no UDP, HTTPS tried (and refused by the plain-HTTP
     DERP, as Go's TLS-only check would be), no latency, and the home is the fallback's, connected.
  10. **disco:** `magicsock_run` with `TSNET_PING=tsnet-peer` disco-pings the peer every 2 s, as `tailscale
      ping` does. The first answer comes over DERP; tsnet sends a CallMeMaybe, and the path goes direct to one of the
      peer's endpoints: its own port 41641, or the port its NAT maps, whichever this machine's network reaches (a hand
      run took the first, CI the second). The peer's own `tailscale ping` gets a direct answer from tsnet
      (counted, not printed: it names this Mac's address). Then the peer moves to port 41642 (`peer-port`) with a new
      disco key: tsnet notices, and the path follows to a port it didn't use before. The peer goes back to 41641
      afterwards.
  11. **wireguard:** WireGuard with tailscaled, both ways. `magicsock_run` with `TSNET_ICMP=tsnet-peer` sends
      ICMP echo requests from its tailnet address: a handshake runs, and the peer's own stack answers through the
      tunnel. Then the peer runs `tailscale ping --icmp` to a second tsnet node: tsnet is the responder, and lwIP
      behind its tunnel answers. Last, the peer's `tailscale nc` to that node's port 7 gets its bytes back from
      tsnet's TCP echo service. Then the packet filter: `headscale policy set` opens only port 22, and the new
      rules reach tsnet in a netmap. The peer's ping still gets answers (any open port opens ICMP), its `tailscale
      ping --tsmp` gets a pong, and its `nc` to port 7 gets nothing back. The policy then goes back to allowing everything, and the script's exit trap does that
      too. The ping's and the echo's results, and the peer's logged TSMP rejects, are counted, not printed (they name
      addresses).
- Nothing here deploys and nothing is secret: the keys are throwaway and live only in the harness's volumes.
- **In CI** (`.github/workflows/ci.yml`): the harness job runs `down`, `up`, `test/test.sh` with `TSNET_HARNESS=1`,
  then `down` again. It uses fixed container names, so don't run the harness by hand on a machine while CI runs there.
