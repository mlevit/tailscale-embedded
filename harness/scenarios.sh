#!/bin/bash
# tsnet's control client against the harness: each scenario runs test/client_run (built by test.sh, which calls
# this with TSNET_HARNESS=1) and checks its output and the control server's view; the DERP scenario runs test/derp_run
# from the same directory, and the DERP regions scenario test/derpmgr_run. Needs `harness.sh up`
# first. About 12 minutes (scenario 11, WireGuard, adds one): the stall scenario waits out the 120 s watchdog twice over, the regions one runs 170 s,
# the netcheck ones (test/magicsock_run) 55 s, and the disco one about 2 minutes with the peer's two
# restarts.
#
#   scenarios.sh <client_run binary>
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:?usage: scenarios.sh <client_run binary>}"
H="$HERE/harness.sh"
URL="http://127.0.0.1:8090"
state="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-client.XXXXXX")"
other="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-other.XXXXXX")"
derp="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-derp.XXXXXX")"
relay_a="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-relay-a.XXXXXX")"
relay_b="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-relay-b.XXXXXX")"
netcheck="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-netcheck.XXXXXX")"
netcheck_b="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-netcheck-b.XXXXXX")"
disco="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-disco.XXXXXX")"
wg_a="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-wg-a.XXXXXX")"
wg_b="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-wg-b.XXXXXX")"
logs="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-scenarios.XXXXXX")"
pids=()
# policy <HuJSON>: sets headscale's policy (database mode). Its image has no shell, so the policy goes in on stdin.
policy() { printf '%s' "$1" | docker exec -i tsnet-harness-headscale headscale policy set -f /dev/stdin >/dev/null; }
ALLOW_ALL='{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}'
policy_set=0
cleanup() {
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done # bash 3.2: an empty array is unset
  "$H" resume 2>/dev/null || true
  if [ "$policy_set" = 1 ]; then policy "$ALLOW_ALL" || true; fi # a hand run's later scenarios need everything open
  rm -rf "$state" "$other" "$derp" "$relay_a" "$relay_b" "$netcheck" "$netcheck_b" "$disco" "$wg_a" "$wg_b" "$logs"
}
trap cleanup EXIT
failures=0

pass() {
  echo "scenario $1: ok"
  grep -E "client_run:|control|derp|harness:|pong from|disco:|icmp echo|tcp echo" "$2" | sed 's/^/  /'
}
fail() {
  echo "scenario $1: FAILED: $2"
  echo "--- its log:"
  cat "$3"
  # The server's side too: in CI the harness goes down after the run, and its logs with it.
  echo "--- headscale's last 40 lines:"
  docker logs --tail 40 tsnet-harness-headscale 2>&1 || true
  failures=$((failures + 1))
}
run() { TSNET_STATE_DIR="$state" "$BIN" "$URL" "$@"; }
# wait_log <log> <from line> <seconds> <pattern>: the pattern appears after line <from> within the time.
wait_log() {
  local end=$((SECONDS + $3))
  until tail -n +"$(($2 + 1))" "$1" | grep -qE "$4"; do
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep 1
  done
}
lines() { wc -l <"$1" | tr -d ' '; }

# Nodes left by an earlier run (or a hand run of client_run or derp_run): each would be an extra peer.
"$H" delete tsnet-client
"$H" delete tsnet-other
"$H" delete tsnet-derp
"$H" delete tsnet-relay-a
"$H" delete tsnet-relay-b
"$H" delete tsnet-netcheck
"$H" delete tsnet-disco
key="$("$H" key | tail -1)"

# 1. A first start with an auth key registers, polls, and sees the harness's peer.
log="$logs/join"
if run 15 "$key" >"$log" 2>&1 && grep -q "state RUNNING" "$log" && grep -q "peers: .*tsnet-peer" "$log" &&
  [ "$("$H" count tsnet-client)" = 1 ]; then
  pass join "$log"
else
  fail join "not RUNNING as one node with tsnet-peer in its netmap" "$log"
fi
node_id="$(sed -n 's/.*node ID \(.*\)$/\1/p' "$log")"

# 2. A restart logs in with the stored node key: the same node, no new registration. It is given the key again, as a
# device with the key built into its image is on every boot, and must not send it.
log="$logs/restart"
if run 10 "$key" >"$log" 2>&1 && grep -q "state RUNNING" "$log" && grep -q "auth key not sent" "$log" &&
  grep -q "node ID $node_id\$" "$log" && [ "$("$H" count tsnet-client)" = 1 ]; then
  pass restart "$log"
else
  fail restart "not RUNNING as the same single node ($node_id)" "$log"
fi

# 3. A peer that joins appears in the netmap, and goes when its node is deleted.
log="$logs/peers"
run 60 >"$log" 2>&1 &
pids+=($!)
ok=0
if wait_log "$log" 0 20 "state RUNNING"; then
  TSNET_STATE_DIR="$other" TSNET_HOSTNAME=tsnet-other "$BIN" "$URL" 12 "$key" >"$logs/other" 2>&1 &
  pids+=($!)
  if wait_log "$log" 0 25 "peers: .*tsnet-other"; then
    from="$(lines "$log")"
    "$H" delete tsnet-other
    if wait_log "$log" "$from" 25 "netmap changed .*, 1 peers: tsnet-peer\.[^,]*$"; then ok=1; fi
  fi
fi
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
if [ "$ok" = 1 ]; then pass peers "$log"; else fail peers "tsnet-other didn't come and go in the netmap" "$log"; fi

# 4. An idle stream stays open past the watchdog (the server's keep-alives reset it). A stalled server trips the watchdog
# ("map response long-poll timed out!"): the stream is reset, and once the server is back a new poll runs on the same
# connection, as tailscaled's does.
log="$logs/stall"
run 400 >"$log" 2>&1 &
pids+=($!)
ok=0
why="not RUNNING"
if wait_log "$log" 0 20 "state RUNNING"; then
  from="$(lines "$log")"
  why="the idle stream ended"
  if ! wait_log "$log" "$from" 135 "map poll:|timed out"; then
    from="$(lines "$log")"
    "$H" stall
    why="the watchdog didn't fire on the stalled server"
    if wait_log "$log" "$from" 160 "long-poll timed out!"; then
      from="$(lines "$log")"
      "$H" resume
      why="no new netmap after the server came back"
      if wait_log "$log" "$from" 60 "netmap changed"; then
        why="it dialed again"
        if [ "$(grep -c "control connection to" "$log")" = 1 ]; then ok=1; fi
      fi
    fi
  fi
fi
"$H" resume 2>/dev/null || true # still frozen if the watchdog never fired
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
if [ "$ok" = 1 ]; then pass stall "$log"; else fail stall "$why" "$log"; fi

# 5. Deleting the node. headscale doesn't answer 404 (Tailscale's server does: NODE_REMOVED, policy_test): each poll
# gets a placeholder self node expired in 1970, then the stream ends. That is NEEDS_AUTH ("node key expired", ipnlocal's
# keyExpired), and the polls go on, the backoff reset by each netmap, as tailscaled's do (measured: 6, 10, 14 ms apart).
log="$logs/removed"
run 25 >"$log" 2>&1 &
pids+=($!)
ok=0
if wait_log "$log" 0 20 "state RUNNING"; then
  "$H" delete tsnet-client
  if wait_log "$log" 0 20 "state NEEDS_AUTH \(node key expired\)"; then
    from="$(grep -n "state NEEDS_AUTH" "$log" | head -1 | cut -d: -f1)"
    if wait_log "$log" "$from" 10 "map poll: ended"; then ok=1; fi # a poll after the one that said so
  fi
fi
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
if [ "$ok" = 1 ]; then pass removed "$log"; else fail removed "no NEEDS_AUTH (node key expired), or polling stopped" "$log"; fi

# 6. DERP: a registered node connects to the harness's DERP server (headscale's embedded one, Tailscale's own
# derpserver), which only accepts registered nodes, and gets ServerInfo, a pong to its ping, its own packet back, and
# PeerGone (not here) for a disco-shaped packet to a key nobody has (test/derp_run.c).
log="$logs/derp"
"$H" delete tsnet-derp
if TSNET_STATE_DIR="$derp" TSNET_HOSTNAME=tsnet-derp TS_DEBUG_USE_DERP_HTTP=1 "$(dirname "$BIN")/derp_run" "$URL" 30 \
  "$key" >"$log" 2>&1 && grep -q "derp_run: done: accepted 1, pong 1, packet from itself 1, not here 1" "$log"; then
  pass derp "$log"
else
  fail derp "no ServerInfo, pong, own packet or not-here from the DERP server" "$log"
fi
"$H" delete tsnet-derp

# 7. DERP regions (test/derpmgr_run.c): node A sends node B five packets over DERP and one over the region
# that isn't its home (derp.yaml has two). Then headscale restarts, and A's connections are dialed again after the
# backoff (connGen=2). The non-home region, unwritten since, closes as idle (cleanStaleDerp: more than 60 s, checked
# every 15 s). A runs 170 s, so its home connection outlives the 120 s read deadline on the server's keep-alives.
log="$logs/relay"
blog="$logs/relay-b"
MGR="$(dirname "$BIN")/derpmgr_run"
"$H" delete tsnet-relay-a
"$H" delete tsnet-relay-b
ok=0
why="B's home never connected"
TSNET_STATE_DIR="$relay_b" TSNET_HOSTNAME=tsnet-relay-b TS_DEBUG_USE_DERP_HTTP=1 "$MGR" "$URL" 200 "$key" >"$blog" 2>&1 &
pids+=($!)
if wait_log "$blog" 0 30 "derp-90[01] connected"; then
  TSNET_STATE_DIR="$relay_a" TSNET_HOSTNAME=tsnet-relay-a TSNET_DERP_TO=tsnet-relay-b TS_DEBUG_USE_DERP_HTTP=1 \
    "$MGR" "$URL" 170 "$key" >"$log" 2>&1 &
  apid=$!
  pids+=("$apid")
  why="B got no packet from A over DERP"
  if wait_log "$blog" 0 40 "packet from .* over derp-90[01]: relay"; then
    why="A opened no connection to its non-home region"
    if wait_log "$log" 0 10 "adding connection to derp-90[01] for \["; then
      from="$(lines "$log")"
      "$H" restart
      why="A wasn't connected again after the restart"
      # connGen counts connections made, as Go's derphttp does, so redials that fail while headscale comes back
      # don't count: the first connection after the restart is the second.
      if wait_log "$log" "$from" 60 "connected; connGen=2"; then
        why="the idle non-home region wasn't closed"
        if wait_log "$log" "$from" 110 "closing connection to derp-90[01] \(idle\)"; then
          why="A's home wasn't connected at the end, or a read deadline fired"
          if wait "$apid" && ! grep -q "no frame in 120 s" "$log"; then ok=1; fi
        fi
      fi
    fi
  fi
fi
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
if [ "$ok" = 1 ]; then pass relay "$log"; else fail relay "$why" "$log"; fi
"$H" delete tsnet-relay-a
"$H" delete tsnet-relay-b

# 8. netcheck (test/magicsock_run.c): magicsock reports on the DERP map (STUN to headscale's STUN server, its
# port published for the Mac), sets the DERP home from the report and connects it, and with the harness's peer in the
# netmap reports again ("non-zero-peers") and then every 20 to 26 s (periodic ReSTUN): at least 3 reports in 40 s.
# The disco key, the endpoints and NetInfo reach control: the harness's peer's netmap has the node's disco
# key, its endpoints and its home DERP (from NetInfo's PreferredDERP).
log="$logs/netcheck"
MS="$(dirname "$BIN")/magicsock_run"
"$H" delete tsnet-netcheck
why="the run failed"
ok=0
seen=""
seen_ok=0
TSNET_STATE_DIR="$netcheck" TSNET_HOSTNAME=tsnet-netcheck TS_DEBUG_USE_DERP_HTTP=1 "$MS" "$URL" 40 "$key" >"$log" 2>&1 &
mpid=$!
pids+=("$mpid")
if wait_log "$log" 0 25 "magicsock_run: [0-9]+ endpoints"; then
  # The lite update, then the peer's next netmap: within 15 s.
  for _ in $(seq 15); do
    seen="$("$H" seen tsnet-netcheck)"
    if echo "$seen" | grep -qE "^disco=1 endpoints=[1-9][0-9]* derp=90[01]$"; then
      seen_ok=1
      break
    fi
    sleep 1
  done
fi
if wait "$mpid"; then
  echo "harness: $seen" >>"$log" # after the run: it writes the log at its own offset
  why="control and the peer don't know the node's disco key, endpoints and home DERP ($seen)"
  if [ "$seen_ok" = 1 ]; then
    why="no report with UDP working and region latencies"
    if grep -qE "netcheck: report: udp=true v4=true .*derpdist=90[01]v4" "$log"; then
      why="the home wasn't set from the report and connected"
      if grep -qE "magicsock: home is now derp-90[01]" "$log" && grep -qE "derp-90[01] connected" "$log"; then
        why="fewer than 3 reports in 40 s (no periodic ReSTUN)"
        if [ "$(grep -c "netcheck: report:" "$log")" -ge 3 ]; then ok=1; fi
      fi
    fi
  fi
fi
pids=()
if [ "$ok" = 1 ]; then pass netcheck "$log"; else fail netcheck "$why" "$log"; fi
"$H" delete tsnet-netcheck

# 9. UDP blocked: the STUN packets are dropped, so a report has no UDP and tries HTTPS (the harness's DERP is
# plain HTTP, so that fails too, as it would for Go's measureHTTPSLatency, which always speaks TLS). With no latency
# and no home yet, the home is pickDERPFallback's, and it connects.
log="$logs/udp-blocked"
"$H" delete tsnet-netcheck
ok=0
if TSNET_STATE_DIR="$netcheck_b" TSNET_HOSTNAME=tsnet-netcheck TS_DEBUG_USE_DERP_HTTP=1 TSNET_DROP_STUN=1 "$MS" "$URL" 15 \
  "$key" >"$log" 2>&1 && grep -q "netcheck: UDP is blocked, trying HTTPS" "$log" &&
  grep -qE "netcheck: report: udp=false .*derp=0 derpdist=$" "$log" &&
  grep -qE "magicsock: home is now derp-90[01]" "$log" && grep -qE "derp-90[01] connected" "$log"; then
  ok=1
fi
if [ "$ok" = 1 ]; then pass udp-blocked "$log"; else fail udp-blocked "no fallback home, or it didn't connect" "$log"; fi
"$H" delete tsnet-netcheck

# 10. disco: tsnet pings the harness's peer every 2 s (magicsock_run's TSNET_PING, "tailscale ping"). The
# first answer comes over DERP (the peer's home); tsnet sends the peer a CallMeMaybe with its endpoints, and the path
# goes direct, to one of the peer's endpoints: its own port (41641), or the one its NAT maps, whichever this machine's
# network reaches and betterAddr prefers (a hand run took the first, CI the second). The peer's own
# `tailscale ping` is answered by tsnet over a direct path too. Then the peer moves to a new port (harness.sh
# peer-port), with a new disco key, as tailscaled makes one each start: tsnet notices the key change and the path
# follows, to a port it didn't use before. The peer goes back to its port afterwards.
# The latest direct pong's port in the disco log after line $1, or nothing.
direct_port() { tail -n +"$(($1 + 1))" "$log" | grep -oE "pong from tsnet-peer via udp port [0-9]+ " | tail -1 | grep -oE "[0-9]+" || true; } # no match must not end the script (set -e, pipefail)
log="$logs/disco"
"$H" delete tsnet-disco
ok=0
why="no answer from the peer, over DERP or direct"
peer_direct=0
TSNET_STATE_DIR="$disco" TSNET_HOSTNAME=tsnet-disco TS_DEBUG_USE_DERP_HTTP=1 TSNET_PING=tsnet-peer "$MS" "$URL" 100 \
  "$key" >"$log" 2>&1 &
pids+=($!)
if wait_log "$log" 0 30 "pong from tsnet-peer via (derp-90[01]|udp port [0-9]+ )"; then
  # tsnet pings the peer's netmap endpoints and DERP at once (endpoint.send), and the first answer wins. On this Mac
  # (OrbStack) the host can't reach a container's address, so DERP answers first and the CallMeMaybe makes the path
  # direct. On plain Linux Docker (GitHub's runners) the direct answer comes first, and no CallMeMaybe is needed.
  first="$(grep -m1 -oE "pong from tsnet-peer via (derp|udp)" "$log" | grep -oE "(derp|udp)$" || true)"
  direct=1
  if [ "$first" = derp ]; then
    direct=0
    why="no CallMeMaybe to the peer"
    if wait_log "$log" 0 10 "sent call-me-maybe to"; then
      why="no direct path to the peer"
      if wait_log "$log" 0 20 "pong from tsnet-peer via udp port [0-9]+ "; then
        direct=1
      fi
    fi
  fi
  if [ "$direct" = 1 ]; then
    old_port="$(direct_port 0)"
    why="the peer's tailscale ping wasn't answered over a direct path"
    # Counted, not printed: a direct pong names this Mac's address.
    peer_direct="$(docker exec tsnet-harness-peer tailscale ping -c 5 --timeout 3s tsnet-disco 2>&1 |
      grep -cE "^pong from tsnet-disco .* via [0-9a-f.:\[]+:[0-9]+ in" || true)"
    if [ "$peer_direct" -ge 1 ]; then
      from="$(lines "$log")"
      "$H" peer-port 41642
      why="the peer's new disco key wasn't noticed"
      if wait_log "$log" "$from" 60 "changed its disco key"; then
        why="the path didn't follow the peer to a new port (it used port $old_port before)"
        for _ in $(seq 30); do
          new_port="$(direct_port "$from")"
          if [ -n "$new_port" ] && [ "$new_port" != "$old_port" ]; then
            ok=1
            break
          fi
          sleep 1
        done
      fi
    fi
  fi
fi
echo "harness: the first answer came over ${first:-nothing}" >>"$log"
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
echo "harness: the peer's tailscale ping: $peer_direct direct pongs" >>"$log"
if [ "$ok" = 1 ]; then pass disco "$log"; else fail disco "$why" "$log"; fi
"$H" peer-port 41641 # back to compose.yaml's port, for whatever runs next
"$H" delete tsnet-disco

# 11. wireguard: WireGuard with the real tailscaled, both ways, through magicsock. tsnet initiates: it sends
# the peer ICMP echo requests from its tailnet address (magicsock_run's TSNET_ICMP), a handshake runs, and the peer's
# own stack answers through the tunnel. Then the peer initiates, to a second tsnet node (`tailscale ping --icmp`):
# tsnet is the responder, and lwIP behind its tunnel answers; then the peer talks TCP to tsnet's echo service
# (`tailscale nc` to port 7) and gets its bytes back. Last, the packet filter: a policy that opens only port 22
# reaches tsnet in a netmap. The peer's ping still gets answers (any open port opens ICMP), its TSMP ping gets a pong,
# and its TCP to port 7 gets nothing back. The policy goes back to allowing everything.
log="$logs/wireguard"
blog="$logs/wireguard-b"
"$H" delete tsnet-wg
"$H" delete tsnet-wg2
ok=0
why="tsnet's echo requests got no reply through the tunnel"
TSNET_STATE_DIR="$wg_a" TSNET_HOSTNAME=tsnet-wg TS_DEBUG_USE_DERP_HTTP=1 TSNET_ICMP=tsnet-peer "$MS" "$URL" 25 \
  "$key" >"$log" 2>&1 || true
if grep -qE "icmp echo reply from 100\.64\." "$log"; then
  why="the peer's ping to tsnet got no answer"
  TSNET_STATE_DIR="$wg_b" TSNET_HOSTNAME=tsnet-wg2 TS_DEBUG_USE_DERP_HTTP=1 "$MS" "$URL" 50 "$key" >"$blog" 2>&1 &
  pids+=($!)
  # Counted, not printed: the peer's output names addresses.
  peer_pongs() {
    docker exec tsnet-harness-peer tailscale ping --icmp -c 3 --timeout 3s tsnet-wg2 2>&1 |
      grep -c "^pong from tsnet-wg2 " || true
  }
  # stdin stays open a moment so nc reads the echo before it closes.
  peer_echo() {
    docker exec tsnet-harness-peer sh -c "(printf tsnet-echo; sleep 3) | timeout $1 tailscale nc tsnet-wg2 7" \
      2>/dev/null || true
  }
  last_rules() { grep -oE "packet filter: [0-9]+ bytes" "$blog" | tail -1 || true; }
  if wait_log "$blog" 0 20 "magicsock_run: [0-9]+ endpoints"; then
    pongs="$(peer_pongs)"
    echo "harness: the peer's ping to tsnet: $pongs pongs" >>"$log"
    if [ "$pongs" -ge 1 ]; then
      why="the peer's TCP to tsnet's echo service didn't come back"
      echoed="$(peer_echo 10)"
      echo "harness: the peer's TCP echo: '$echoed'" >>"$log"
      if [ "$echoed" = "tsnet-echo" ]; then
        why="headscale refused the policy with only port 22 open"
        before="$(last_rules)"
        since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        policy_set=1
        if policy '{"acls":[{"action":"accept","src":["*"],"dst":["*:22"]}]}'; then
          why="with only port 22 open, the new rules didn't reach tsnet"
          end=$((SECONDS + 10))
          until [ "$(last_rules)" != "$before" ] || [ "$SECONDS" -ge "$end" ]; do sleep 1; done
        fi
        if [ "$(last_rules)" != "$before" ]; then
          echo "harness: port 22 only: tsnet's rules went from '$before' to '$(last_rules)'" >>"$log"
          pongs="$(peer_pongs)"
          echoed="$(peer_echo 5)"
          rejects="$(docker logs --since "$since" tsnet-harness-peer 2>&1 | grep -c "rejected due to acl" || true)"
          # A TSMP ping gets its pong whatever the rules say.
          tsmp="$(docker exec tsnet-harness-peer tailscale ping --tsmp -c 2 --timeout 3s tsnet-wg2 2>&1 |
            grep -c "^pong from tsnet-wg2 .* via TSMP" || true)"
          echo "harness: port 22 only: $pongs pongs, TCP echo '$echoed', $tsmp TSMP pongs, $rejects TSMP rejects logged" \
            >>"$log"
          why="with only port 22 open, the peer's ping or TSMP ping failed, or its TCP to port 7 got through"
          if [ "$pongs" -ge 1 ] && [ "$tsmp" -ge 1 ] && [ -z "$echoed" ]; then ok=1; fi
        fi
        policy "$ALLOW_ALL" || true # else the cleanup tries again
        policy_set=0
      fi
    fi
  fi
fi
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
pids=()
grep -E "icmp echo request from|tcp echo" "$blog" >>"$log" 2>/dev/null || true
if [ "$ok" = 1 ]; then pass wireguard "$log"; else fail wireguard "$why" "$log"; fi
"$H" delete tsnet-wg
"$H" delete tsnet-wg2

if [ "$failures" != 0 ]; then
  echo "tsnet harness scenarios: $failures failed"
  exit 1
fi
echo "tsnet harness scenarios: ok"
