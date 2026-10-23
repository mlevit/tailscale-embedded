#!/bin/bash
# Downloads the libraries the host tests link, at the versions ESP-IDF v5.5.6 ships, checks each against its sha256 and
# unpacks it into $1 (test/test.sh passes $TSNET_HOST_BUILD/deps). A directory already there is reused.
#   - mbedTLS 3.6.7 (Mbed-TLS's release tarball; the sum is the one the release publishes)
#   - cJSON 1.7.19 (DaveGamble/cJSON at the v1.7.19 tag)
#   - lwIP: espressif/esp-lwip at the commit ESP-IDF v5.5.6 pins, the stack the device runs
set -euo pipefail

DEST="$1"
mkdir -p "$DEST"

fetch() { # fetch <name> <url> <sha256>
  local name="$1" url="$2" sum="$3"
  [ -d "$DEST/$name" ] && return 0
  local work
  work="$(mktemp -d "${TMPDIR:-/tmp}/tsnet-deps.XXXXXX")"
  curl -sSfL -o "$work/archive" "$url"
  local got
  if command -v sha256sum >/dev/null; then
    got="$(sha256sum "$work/archive" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$work/archive" | cut -d' ' -f1)"
  fi
  if [ "$got" != "$sum" ]; then
    echo "fetch_deps: $name: sha256 $got, expected $sum" >&2
    rm -rf "$work"
    exit 1
  fi
  mkdir "$work/x"
  tar -xf "$work/archive" -C "$work/x"
  # Each archive holds one top-level directory; it's moved into place whole, so a half-unpacked copy never stays.
  mv "$work/x"/* "$DEST/$name"
  rm -rf "$work"
}

fetch mbedtls https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2 \
  a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
fetch cjson https://github.com/DaveGamble/cJSON/archive/c859b25da02955fef659d658b8f324b5cde87be3.tar.gz \
  880a86445ad5cf38f877bac31198268d8fac5d2ce996ebf55d3066a4109ddd8d
fetch lwip https://github.com/espressif/esp-lwip/archive/c6f2f878e7b0f86033214b85547d579be43351e3.tar.gz \
  a7db02542a98b796d251645beb3c739289b543edf32468db3d0618b10f0a84f3
