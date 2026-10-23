#!/bin/bash
# tsnet's conformance harness: headscale and a real tailscaled peer in Docker, on 127.0.0.1:8090. See README.md.
#
#   harness.sh up            start headscale, create the user, join the peer, wait until it's online
#   harness.sh key           mint a reusable, ephemeral preauth key (1 h) for a tsnet client, and print it
#   harness.sh nodes         headscale's node list
#   harness.sh count NAME    how many nodes have hostname NAME
#   harness.sh delete NAME   delete every node with hostname NAME (a node removed from the tailnet)
#   harness.sh seen NAME     the peer's netmap of node NAME: disco key set, endpoint count, home DERP
#   harness.sh probe        tsnet's probe and client scenarios against headscale (test/test.sh with TSNET_HARNESS=1)
#   harness.sh stall|resume  freeze or thaw the control server (docker pause): a stalled map stream
#   harness.sh restart       restart the control server
#   harness.sh peer-port N   restart the peer on UDP port N (its state kept): a peer moving to a new port
#   harness.sh peer-stop|peer-start
#   harness.sh down          stop it all and delete its volumes
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="http://127.0.0.1:8090"
USER_NAME="tsnet"
compose() { docker compose -f "$HERE/compose.yaml" "$@"; }
hs() { docker exec tsnet-harness-headscale headscale "$@"; }

wait_for() { # wait_for <what> <seconds> <command...>
  local what="$1" secs="$2"
  shift 2
  local end=$((SECONDS + secs))
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$end" ]; then
      echo "harness: $what didn't happen in ${secs}s" >&2
      return 1
    fi
    sleep 1
  done
}

user_id() {
  hs users list -o json | python3 -I -c 'import json,sys
for u in json.load(sys.stdin) or []:
    if u.get("name") == sys.argv[1]: print(u["id"]); break' "$USER_NAME"
}

mint() { # mint [--ephemeral]
  hs preauthkeys create --user "$(user_id)" --reusable --expiration 1h "$@" -o json |
    python3 -I -c 'import json,sys; print(json.load(sys.stdin)["key"])'
}

# The ids of the nodes whose hostname is $1, one per line.
node_ids() {
  hs nodes list -o json | python3 -I -c 'import json,sys
for n in json.load(sys.stdin) or []:
    if n.get("name") == sys.argv[1]: print(n["id"])' "$1"
}

# The peer itself says it's running (headscale's own "online" flag lags, and stays true for a while after the peer has
# died, which once hid a peer that couldn't rejoin).
peer_online() {
  [ "$(docker inspect -f '{{.State.Running}}' tsnet-harness-peer 2>/dev/null)" = true ] &&
    docker exec tsnet-harness-peer tailscale status --json 2>/dev/null |
    python3 -I -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("BackendState") == "Running" else 1)'
}

# What the harness's peer knows of the node with hostname $1, from its netmap (`tailscale debug netmap`: the peer as
# control sent it), as counts, since its endpoints are this machine's addresses and are never printed:
# "disco=1 endpoints=N derp=R" (a non-zero disco key, N endpoints, home DERP region R). (`tailscale status`'s Addrs
# won't do: Go fills it for the node itself only.)
seen() {
  docker exec tsnet-harness-peer tailscale debug netmap | python3 -I -c 'import json,sys
for p in json.load(sys.stdin).get("Peers") or []:
    if (p.get("Hostinfo") or {}).get("Hostname") == sys.argv[1]:
        k = p.get("DiscoKey") or ""
        disco = 1 if k.startswith("discokey:") and k[9:].strip("0") else 0
        print("disco=%d endpoints=%d derp=%d" % (disco, len(p.get("Endpoints") or []), p.get("HomeDERP") or 0)); break
else:
    print("disco=0 endpoints=0 derp=0")' "$1"
}

case "${1:-}" in
  up)
    compose up -d headscale
    wait_for "headscale /health" 30 curl -fsS "$URL/health"
    if [ -z "$(user_id)" ]; then
      hs users create "$USER_NAME" >/dev/null
    fi
    PEER_AUTHKEY="$(mint)" compose up -d peer
    wait_for "the peer coming online" 60 peer_online
    echo "harness: headscale at $URL, peer tsnet-peer online"
    ;;
  key) mint --ephemeral ;;
  nodes) hs nodes list ;;
  count) node_ids "${2:?usage: harness.sh count <hostname>}" | wc -l | tr -d ' ' ;;
  seen) seen "${2:?usage: harness.sh seen <hostname>}" ;;
  delete)
    for id in $(node_ids "${2:?usage: harness.sh delete <hostname>}"); do
      hs nodes delete --identifier "$id" --force >/dev/null
    done
    ;;
  probe) TSNET_HARNESS=1 "$HERE/../test/test.sh" ;;
  stall) docker pause tsnet-harness-headscale ;;
  resume) docker unpause tsnet-harness-headscale ;;
  restart)
    docker restart tsnet-harness-headscale >/dev/null
    wait_for "headscale /health" 30 curl -fsS "$URL/health"
    ;;
  peer-port)
    PEER_PORT="${2:?usage: harness.sh peer-port <udp port>}" compose up -d --force-recreate peer
    wait_for "the peer coming online" 60 peer_online
    ;;
  peer-stop) docker stop tsnet-harness-peer >/dev/null ;;
  peer-start)
    docker start tsnet-harness-peer >/dev/null
    wait_for "the peer coming online" 60 peer_online
    ;;
  down) compose down -v ;;
  *)
    sed -n '3,15p' "$0" >&2
    exit 2
    ;;
esac
