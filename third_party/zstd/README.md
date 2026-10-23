# zstd (vendored, decoder only)

Zstandard's decoder, for control's map responses: the official client always asks for `Compress: "zstd"` and decodes
each map message (`control/controlclient/direct.go`, `decodeMsg`).

- **Source:** zstd **v1.5.7** (2025-02-19), the release tarball `zstd-1.5.7.tar.gz`. Its SHA-256 is
  `eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3`, matching the release's `.sha256` file. Its
  signature checks out against "Zstandard Release Signing Key <signing@zstd.net>"
  (`4EF4AC63455FC9F4545D9B7DEF8FE99528B52FFD`).
- **Copied unmodified:** `lib/common` (without `pool.*` and `threading.*`, which only multithreaded compression uses),
  `lib/decompress` (without `huf_decompress_amd64.S`, x86-64 only), `lib/zstd.h`, `lib/zstd_errors.h` and `LICENSE`.
  zstd is dual-licensed BSD or GPLv2; this project takes it under BSD. There are no local patches: an update copies a
  new release the same way.
- Built with `ZSTD_DISABLE_ASM=1` (the root `CMakeLists.txt` and `test/test.sh`).
