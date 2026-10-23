# tailscale-embedded as one ESP-IDF component: tsnet's core and ESP-IDF back end, with the vendored zstd decoder,
# Monocypher (Ed25519) and TweetNaCl (NaCl box) built in. The host tests don't use this file (test/test.sh).
set(zstd third_party/zstd/lib)
set(vendored
    "${zstd}/common/debug.c" "${zstd}/common/entropy_common.c" "${zstd}/common/error_private.c"
    "${zstd}/common/fse_decompress.c" "${zstd}/common/xxhash.c" "${zstd}/common/zstd_common.c"
    "${zstd}/decompress/huf_decompress.c" "${zstd}/decompress/zstd_ddict.c"
    "${zstd}/decompress/zstd_decompress.c" "${zstd}/decompress/zstd_decompress_block.c"
    "third_party/monocypher/src/monocypher.c" "third_party/monocypher/src/optional/monocypher-ed25519.c"
    "third_party/tweetnacl/src/tweetnacl.c")
idf_component_register(
    SRCS "src/crypto.c" "src/blake2s.c" "src/noise.c" "src/http1.c" "src/tls.c" "src/controlhttp.c" "src/controlkey.c"
         "src/hpack.c" "src/h2.c" "src/tailcfg.c" "src/mapresp.c" "src/mapmsg.c" "src/netmap.c" "src/identity.c"
         "src/policy.c" "src/client.c" "src/derp.c" "src/derphttp.c" "src/derpmgr.c" "src/stun.c" "src/ncplan.c"
         "src/netcheck.c" "src/magicsock.c" "src/disco.c" "src/endpoint.c" "src/selfeps.c" "src/wg.c" "src/wgdev.c"
         "src/allowedips.c" "src/tun.c" "src/filter.c" "src/server.c" "src/json.c"
         "platform/esp/platform_esp.c" "platform/net_posix.c"
         ${vendored}
    INCLUDE_DIRS "src"
    PRIV_INCLUDE_DIRS "${zstd}" "third_party/monocypher/src" "third_party/monocypher/src/optional" "third_party/tweetnacl/src"
    REQUIRES mbedtls esp_timer log esp_hw_support lwip esp_netif vfs json nvs_flash)
target_compile_definitions(${COMPONENT_LIB} PRIVATE ZSTD_DISABLE_ASM=1)
# The vendored libraries are copied unmodified; their warnings aren't this project's (zstd's huf_decompress.c trips
# -Werror=maybe-uninitialized at -Og, ESP-IDF's default), and test/test.sh builds them with -w too.
set_source_files_properties(${vendored} PROPERTIES COMPILE_OPTIONS "-w")
