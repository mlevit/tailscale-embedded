#!/bin/bash
# Host tests of tsnet, on macOS or Linux, under ASan and UBSan. They link mbedTLS, cJSON and lwIP: ESP-IDF's own copies
# when IDF_PATH is set, else the releases tools/fetch_deps.sh pins (the same versions). mbedTLS is built once with its
# default config into a cached library outside the repo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSNET="$(cd "$HERE/.." && pwd)"
BUILD="${TSNET_HOST_BUILD:-$HOME/.cache/tailscale-embedded}"
if [ -n "${IDF_PATH:-}" ]; then
  MBEDTLS="$IDF_PATH/components/mbedtls/mbedtls"
  CJSON="$IDF_PATH/components/json/cJSON"
  LWIP="$IDF_PATH/components/lwip/lwip/src"
else
  "$TSNET/tools/fetch_deps.sh" "$BUILD/deps"
  MBEDTLS="$BUILD/deps/mbedtls"
  CJSON="$BUILD/deps/cjson"
  LWIP="$BUILD/deps/lwip/src"
fi

ver="$(grep -m1 'define MBEDTLS_VERSION_STRING ' "$MBEDTLS/include/mbedtls/build_info.h" | cut -d'"' -f2)"
lib="$BUILD/libmbedcrypto-$ver.a"
if [ ! -f "$lib" ]; then
  # Built in a directory of its own and moved into place, so an interrupted or concurrent build never leaves half a library.
  work="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-mbedtls.XXXXXX")"
  # The inner script is single-quoted on purpose: it gets its paths as $1 to $3, one object file per job.
  # shellcheck disable=SC2016
  find "$MBEDTLS/library" -maxdepth 1 -name '*.c' -print0 |
    xargs -0 -P 8 -I{} sh -c 'cc -O2 -I "$1/include" -I "$1/library" -c "$2" -o "$3/$(basename "$2" .c).o"' _ "$MBEDTLS" {} "$work"
  ar rcs "$work/lib.a" "$work"/*.o
  mkdir -p "$BUILD"
  mv "$work/lib.a" "$lib"
  rm -rf "$work"
fi

out="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-test.XXXXXX")"
trap 'rm -rf "$out"' EXIT
cc -O1 -w -fsanitize=address,undefined -c "$CJSON/cJSON.c" -o "$out/cJSON.o" # cJSON (its sprintf warnings aren't ours)
# The vendored zstd decoder (third_party/zstd), as its CMakeLists.txt builds it; its warnings aren't ours either.
ZSTD="$TSNET/third_party/zstd/lib"
zstd_objs=()
for f in "$ZSTD"/common/*.c "$ZSTD"/decompress/*.c; do
  o="$out/zstd-$(basename "$f" .c).o"
  cc -O1 -w -fsanitize=address,undefined -DZSTD_DISABLE_ASM=1 -I "$ZSTD" -c "$f" -o "$o"
  zstd_objs+=("$o")
done
# The vendored Monocypher (third_party/monocypher), for the Ed25519 NL key.
MONO="$TSNET/third_party/monocypher/src"
cc -O1 -w -fsanitize=address,undefined -I "$MONO" -c "$MONO/monocypher.c" -o "$out/monocypher.o"
cc -O1 -w -fsanitize=address,undefined -I "$MONO" -c "$MONO/optional/monocypher-ed25519.c" -o "$out/monocypher-ed25519.o"
# The vendored TweetNaCl (third_party/tweetnacl), for NaCl box's HSalsa20 and XSalsa20-Poly1305.
NACL="$TSNET/third_party/tweetnacl/src"
cc -O1 -w -fsanitize=address,undefined -I "$NACL" -c "$NACL/tweetnacl.c" -o "$out/tweetnacl.o"
# lwIP (ESP-IDF's fork, the device's own stack), for the tunnel's IP side (tun.c): NO_SYS, IPv4, with test/lwip's
# options; its warnings aren't ours. sys_arch.c gives it the time.
LWIP_INC=(-I "$TSNET/test/lwip" -I "$LWIP/include")
lwip_objs=()
for f in "$LWIP"/core/{init,def,inet_chksum,ip,mem,memp,netif,pbuf,raw,stats,sys,tcp,tcp_in,tcp_out,timeouts,udp}.c \
  "$LWIP"/core/ipv4/{icmp,ip4,ip4_addr}.c "$TSNET/test/lwip/sys_arch.c"; do
  o="$out/lwip-$(basename "$f" .c).o"
  cc -O1 -w -fsanitize=address,undefined "${LWIP_INC[@]}" -I "$TSNET/src" -c "$f" -o "$o"
  lwip_objs+=("$o")
done
# UBSan stops the test at its first report: by default it prints and goes on, and two reports passed unnoticed.
CFLAGS=(-std=c11 -Wall -Wextra -Werror -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=undefined
  -DZSTD_DISABLE_ASM=1 -I "$TSNET/src" -I "$TSNET/test"
  -I "$MBEDTLS/include" -I "$CJSON" -I "$ZSTD" -I "$MONO" -I "$MONO/optional" -I "$NACL" "${LWIP_INC[@]}")
CORE=("$TSNET/src/crypto.c" "$TSNET/src/blake2s.c" "$TSNET/src/noise.c" "$TSNET/src/http1.c" "$TSNET/src/tls.c"
  "$TSNET/src/controlhttp.c" "$TSNET/src/controlkey.c" "$TSNET/src/hpack.c" "$TSNET/src/h2.c" "$TSNET/src/tailcfg.c"
  "$TSNET/src/mapresp.c" "$TSNET/src/mapmsg.c" "$TSNET/src/netmap.c" "$TSNET/src/identity.c" "$TSNET/src/policy.c"
  "$TSNET/src/client.c" "$TSNET/src/derp.c" "$TSNET/src/derphttp.c" "$TSNET/src/derpmgr.c" "$TSNET/src/stun.c"
  "$TSNET/src/ncplan.c" "$TSNET/src/netcheck.c" "$TSNET/src/magicsock.c" "$TSNET/src/disco.c" "$TSNET/src/endpoint.c" "$TSNET/src/selfeps.c" "$TSNET/src/wg.c" "$TSNET/src/wgdev.c" "$TSNET/src/allowedips.c" "$TSNET/src/tun.c" "$TSNET/src/filter.c" "$TSNET/src/server.c" "$TSNET/src/json.c"
  "$TSNET/platform/host/platform_host.c"
  "$TSNET/platform/net_posix.c")
TESTS=(crypto_test noise_test http1_test controlkey_test controlhttp_test hpack_test h2_test tailcfg_test mapmsg_test
  netmap_test identity_test policy_test derp_test derphttp_test derpmgr_test stun_test ncplan_test netcheck_test magicsock_test disco_test endpoint_test selfeps_test wg_test wgdev_test wgnode_test allowedips_test tun_test filter_test json_test fuzz_test)
TOOLS=(probe capture client_run derp_run derp_probe derpmgr_run magicsock_run)
# tsnet's sources are compiled once, 8 at a time, and every binary links the objects: compiling all of them into each
# of the 37 binaries took most of the run. The inner scripts are single-quoted on purpose: they get their paths and
# flags as arguments.
mkdir "$out/core"
# shellcheck disable=SC2016
printf '%s\0' "${CORE[@]}" |
  xargs -0 -P 8 -I{} sh -c 'f="$1" d="$2"; shift 2; cc "$@" -c "$f" -o "$d/$(basename "$f" .c).o"' _ {} "$out/core" "${CFLAGS[@]}"
LINK=("$out"/core/*.o "$out/cJSON.o" "${zstd_objs[@]}" "$out/monocypher.o" "$out/monocypher-ed25519.o" "$out/tweetnacl.o"
  "${lwip_objs[@]}" "$lib" -lm)
# shellcheck disable=SC2016
printf '%s\0' "${TESTS[@]}" "${TOOLS[@]}" |
  xargs -0 -P 8 -I{} sh -c 't="$1" s="$2" d="$3"; shift 3; cc "$s/$t.c" "$@" -o "$d/$t"' _ {} "$TSNET/test" "$out" \
    "${CFLAGS[@]}" "${LINK[@]}"
for t in "${TESTS[@]}"; do
  if [ "$t" = h2_test ] || [ "$t" = derp_test ] || [ "$t" = fuzz_test ]; then
    TSNET_LOG_QUIET=1 "$out/$t" # their garbage rounds log thousands of errors on purpose
  else
    "$out/$t" "$TSNET/test/fixtures" # the tests that read fixtures take their directory
  fi
done
# The live check against Tailscale's control server needs the network: TSNET_LIVE=1 (docs/design.md, Testing).
if [ "${TSNET_LIVE:-0}" = 1 ]; then
  "$out/probe" https://controlplane.tailscale.com 131 80
  "$out/probe" https://controlplane.tailscale.com 131 443
  "$out/probe"
  # DERP's TLS against one of Tailscale's DERP nodes (named in Tailscale's DERP map), and two bad certificates; then
  # netcheck's HTTPS latency check and a STUN request against the same node.
  "$out/derp_probe" derp1f.tailscale.com
  "$out/derp_probe" derp1f.tailscale.com latency
  "$out/derp_probe" derp1f.tailscale.com stun
  for bad in wrong.host.badssl.com self-signed.badssl.com; do
    if "$out/derp_probe" "$bad"; then
      echo "derp_probe: $bad's bad certificate was accepted" >&2
      exit 1
    fi
  done
fi
# The same against the harness's headscale (harness/harness.sh up first): TSNET_HARNESS=1 (docs/design.md, Testing).
if [ "${TSNET_HARNESS:-0}" = 1 ]; then
  "$out/probe" http://127.0.0.1:8090 131
  "$TSNET/harness/scenarios.sh" "$out/client_run"
fi
