#!/bin/bash
# Writes test/fixtures/zstd/ for mapmsg_test.c.
#   tools/zstd_fixtures.sh <zstd CLI> [<dir of a capture made with Compress "zstd">]
# The CLI is the reference one, built from the same zstd 1.5.7 release as third_party/zstd (make -C programs zstd).
# From a capture (test/capture.c ... zstd), the server's own frames are copied when they hold no address of this
# network (the ControlTime deltas); the big first message is decoded, scrubbed and re-encoded by the CLI instead.
set -euo pipefail
ZSTD="$1"
CAPTURE="${2:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$HERE/test/fixtures/zstd"
mkdir -p "$OUT"
work="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-zstd.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# A real map message's JSON (already scrubbed), single-segment with a checksum as Tailscale's zstdframe writes.
"$ZSTD" -q -f -3 --content-size --check "$HERE/test/fixtures/headscale/map-01.json" -o "$OUT/map-01.zst"
# The keep-alive message.
printf '{"KeepAlive":true}' >"$work/ka"
"$ZSTD" -q -f -3 "$work/ka" -o "$OUT/keepalive.zst"
# Two frames in one message: zstd decodes every frame (zstdframe.AppendDecode).
printf '{"ControlTime":' >"$work/a"
printf '"2026-10-23T01:31:30Z"}' >"$work/b"
"$ZSTD" -q -f "$work/a" -o "$work/a.zst"
"$ZSTD" -q -f "$work/b" -o "$work/b.zst"
cat "$work/a.zst" "$work/b.zst" >"$OUT/two-frames.zst"
# A bomb: 9 MB of zeros, a few hundred bytes compressed, more than the decoded cap.
head -c 9437184 /dev/zero >"$work/zeros"
"$ZSTD" -q -f -19 "$work/zeros" -o "$OUT/bomb.zst"
# A frame whose window (32 MB) is over the cap, although its content is small.
head -c 65536 /dev/zero | tr '\0' 'x' >"$work/xs"
"$ZSTD" -q -f --long=25 --no-content-size <"$work/xs" >"$OUT/big-window.zst"

if [ -n "$CAPTURE" ]; then
  for f in "$CAPTURE"/map-*.bin; do
    if "$ZSTD" -q -dc "$f" | grep -q '"Peers\|"Node\|Endpoints'; then
      continue # holds addresses: covered by map-01.zst above
    fi
    cp "$f" "$OUT/headscale-$(basename "$f" .bin).zst"
  done
fi
ls -l "$OUT"
