#!/usr/bin/env bash
#
# build-libssh2.sh: builds Binary/Libssh2.xcframework, the libssh2 + Mbed TLS that SSHKit links on Apple platforms
# (macOS arm64, iOS arm64, iOS simulator arm64), in one pass from pinned sources:
#
#   1. libssh2 and Mbed TLS cloned at their tags, each checked against the commit pinned below;
#   2. Patches/libssh2/*.patch applied (the same patches as Sources/CLibssh2, which Linux and Windows build);
#   3. one static archive per slice (libssh2 + mbedcrypto + mbedx509 + mbedtls + everest + p256m);
#   4. every Mbed TLS / PSA symbol renamed with a _dbpro_ prefix and the mbedtls/psa headers dropped: Database also
#      links DuckDB, which bundles its own Mbed TLS, and Xcode merges every xcframework's headers into one folder;
#   5. Binary/Libssh2.xcframework, plus Binary/Libssh2.sbom.txt (versions, commits, patches, SHA-256 of each slice).
#
# Package.swift uses Binary/Libssh2.xcframework when it's there (the local build), else the release asset.
# Scripts/release-libssh2.sh zips it, bumps Package.swift and writes what Dev publishes.
#
# Before each rebuild, check for advisories:
#   libssh2:  https://libssh2.org/ (Security), https://github.com/libssh2/libssh2/security/advisories,
#             https://security-tracker.debian.org/tracker/source-package/libssh2
#   Mbed TLS: https://mbed-tls.readthedocs.io/en/latest/security-advisories/ (take the newest 3.6.x LTS release)
#
# Needs Xcode, cmake and llvm-objcopy (brew install cmake llvm), git and network for the first clone.
#
#   Scripts/build-libssh2.sh          build
#   Scripts/build-libssh2.sh clean    remove the scratch folder and the xcframework
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/Binary/Libssh2.xcframework"
SBOM="$ROOT/Binary/Libssh2.sbom.txt"
WORK="${LIBSSH2_BUILD_DIR:-$ROOT/.build/libssh2}"
PATCHES="$ROOT/Patches/libssh2"

LIBSSH2_VERSION="1.11.1"
LIBSSH2_COMMIT="a312b43325e3383c865a87bb1d26cb52e3292641"   # tag libssh2-1.11.1
MBEDTLS_VERSION="3.6.7"
MBEDTLS_COMMIT="068ff080b369adfac81509f9b57b2afabaf82dc5"   # tag mbedtls-3.6.7

IOS_DEPLOY="13.0"
SIM_DEPLOY="15.0"
MACOS_DEPLOY="14.0"

info() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

OBJCOPY="${OBJCOPY:-$(command -v llvm-objcopy || echo /opt/homebrew/opt/llvm/bin/llvm-objcopy)}"
CC="$(xcrun --find clang)"

if [ "${1:-}" = clean ]; then
  rm -rf "$WORK" "$OUT" "$SBOM"
  info "cleaned"
  exit 0
fi
command -v cmake >/dev/null || die "cmake not found (brew install cmake)"
[ -x "$OBJCOPY" ] || die "llvm-objcopy not found (brew install llvm, or OBJCOPY=…)"
mkdir -p "$WORK"

# A clone at the tag whose commit must be the pinned one (a moved tag stops the build).
fetch() {
  local name="$1" url="$2" tag="$3" commit="$4" dir="$WORK/$1"
  if [ ! -d "$dir/.git" ]; then
    info "cloning $name $tag"
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$tag" --recurse-submodules --shallow-submodules "$url" "$dir" \
      || die "cloning $name failed"
  fi
  git -C "$dir" reset -q --hard && git -C "$dir" clean -qfdx
  local head
  head="$(git -C "$dir" rev-parse HEAD)"
  [ "$head" = "$commit" ] || die "$name $tag is $head, not the pinned $commit"
}

fetch libssh2 https://github.com/libssh2/libssh2 "libssh2-$LIBSSH2_VERSION" "$LIBSSH2_COMMIT"
fetch mbedtls https://github.com/Mbed-TLS/mbedtls "mbedtls-$MBEDTLS_VERSION" "$MBEDTLS_COMMIT"
[ -f "$WORK/mbedtls/framework/CMakeLists.txt" ] || die "Mbed TLS's framework submodule is missing"

for patch in "$PATCHES"/*.patch; do
  info "patch $(basename "$patch")"
  git -C "$WORK/libssh2" apply "$patch" || die "$(basename "$patch") doesn't apply"
done

# name, CMAKE_SYSTEM_NAME (empty: macOS), SDK, arch, deployment target
SLICES=(
  "ios-device|iOS|iphoneos|arm64|$IOS_DEPLOY"
  "sim-arm64|iOS|iphonesimulator|arm64|$SIM_DEPLOY"
  "macos||macosx|arm64|$MACOS_DEPLOY"
)

build_slice() {
  local name="$1" system="$2" sdk="$3" arch="$4" deploy="$5"
  local sysroot mt="$WORK/slices/$name/mbedtls" ls="$WORK/slices/$name/libssh2"
  sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
  local common=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$CC" -DCMAKE_OSX_ARCHITECTURES="$arch"
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$deploy")
  [ -n "$system" ] && common+=(-DCMAKE_SYSTEM_NAME="$system" -DCMAKE_OSX_SYSROOT="$sysroot")
  rm -rf "$mt" "$ls"

  info "Mbed TLS $name"
  cmake -S "$WORK/mbedtls" -B "$mt" "${common[@]}" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
    -DUNSAFE_BUILD=OFF -DMBEDTLS_FATAL_WARNINGS=OFF >"$WORK/$name-mbedtls.log" 2>&1 || die "Mbed TLS configure $name"
  cmake --build "$mt" -j8 --target mbedcrypto mbedx509 mbedtls >>"$WORK/$name-mbedtls.log" 2>&1 \
    || die "Mbed TLS build $name (log: $WORK/$name-mbedtls.log)"
  cmake --install "$mt" --prefix "$mt/install" >>"$WORK/$name-mbedtls.log" 2>&1 || die "Mbed TLS install $name"

  info "libssh2 $name"
  cmake -S "$WORK/libssh2" -B "$ls" "${common[@]}" -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
    -DCRYPTO_BACKEND=mbedTLS -DMBEDTLS_INCLUDE_DIR="$mt/install/include" \
    -DMBEDCRYPTO_LIBRARY="$mt/install/lib/libmbedcrypto.a" >"$WORK/$name-libssh2.log" 2>&1 \
    || die "libssh2 configure $name (log: $WORK/$name-libssh2.log)"
  cmake --build "$ls" -j8 >>"$WORK/$name-libssh2.log" 2>&1 || die "libssh2 build $name (log: $WORK/$name-libssh2.log)"
  lipo -info "$ls/src/libssh2.a" | grep -q "$arch" || die "libssh2 $name isn't $arch"
  if nm "$ls/src/libssh2.a" 2>/dev/null | grep -qiE "OPENSSL|SSL_"; then die "libssh2 $name references OpenSSL"; fi

  local lib="$mt/install/lib" merged="$WORK/slices/$name/libssh2_all.a"
  libtool -static -o "$merged" "$ls/src/libssh2.a" "$lib/libmbedcrypto.a" "$lib/libmbedx509.a" "$lib/libmbedtls.a" \
    "$lib/libeverest.a" "$lib/libp256m.a" 2>/dev/null || die "merging $name"
}

for slice in "${SLICES[@]}"; do
  IFS='|' read -r name system sdk arch deploy <<<"$slice"
  build_slice "$name" "$system" "$sdk" "$arch" "$deploy"
done

# 4. The _dbpro_ prefix, from the symbols every slice defines.
MAP="$WORK/prefix-map.txt"
for slice in "${SLICES[@]}"; do nm -g "$WORK/slices/${slice%%|*}/libssh2_all.a" 2>/dev/null; done | awk '{print $NF}' \
  | grep -E '^_(mbedtls|psa|mbedcrypto|tf_psa)' | sort -u | awk '{n = $1; sub(/^_/, "_dbpro_", n); print $1, n}' >"$MAP"
info "prefixing $(wc -l <"$MAP" | tr -d ' ') Mbed TLS / PSA symbols with _dbpro_"
for slice in "${SLICES[@]}"; do
  lib="$WORK/slices/${slice%%|*}/libssh2_all.a"
  "$OBJCOPY" --redefine-syms="$MAP" "$lib" "$lib.tmp" && mv "$lib.tmp" "$lib"
  left=$(nm -g "$lib" | awk '$2 != "U" {print $NF}' | grep -c '^_mbedtls' || true)
  [ "$left" = 0 ] || die "$left Mbed TLS symbols are still unprefixed in ${slice%%|*}"
done

# Headers: libssh2's public ones and the CLibssh2 module map (Headers/CLibssh2/module.modulemap: Xcode copies every
# xcframework's Headers into one include folder, where a second Headers/module.modulemap would clash).
HEADERS="$WORK/headers"
rm -rf "$HEADERS" && mkdir -p "$HEADERS/CLibssh2"
cp "$WORK/libssh2/include/libssh2.h" "$WORK/libssh2/include/libssh2_publickey.h" "$WORK/libssh2/include/libssh2_sftp.h" \
  "$HEADERS/"
cat >"$HEADERS/CLibssh2/module.modulemap" <<'EOF'
module CLibssh2 [system] {
    header "../libssh2.h"
    header "../libssh2_sftp.h"
    export *
}
EOF

rm -rf "$OUT" && mkdir -p "$(dirname "$OUT")"
xcodebuild -create-xcframework \
  -library "$WORK/slices/macos/libssh2_all.a" -headers "$HEADERS" \
  -library "$WORK/slices/ios-device/libssh2_all.a" -headers "$HEADERS" \
  -library "$WORK/slices/sim-arm64/libssh2_all.a" -headers "$HEADERS" \
  -output "$OUT" >/dev/null || die "xcodebuild -create-xcframework failed"

version=$(strings "$WORK/slices/macos/libssh2_all.a" | grep -m1 -E '^Mbed TLS [0-9]' || true)
[ "$version" = "Mbed TLS $MBEDTLS_VERSION" ] || die "the archive says '$version', not Mbed TLS $MBEDTLS_VERSION"
{
  echo "Libssh2.xcframework, built $(date -u +%Y-%m-%dT%H:%M:%SZ) by SSH's Scripts/build-libssh2.sh"
  echo "libssh2 $LIBSSH2_VERSION  commit $LIBSSH2_COMMIT  (https://github.com/libssh2/libssh2)"
  for patch in "$PATCHES"/*.patch; do
    echo "  patch $(basename "$patch")  sha256 $(shasum -a 256 "$patch" | cut -d' ' -f1)"
  done
  echo "Mbed TLS $MBEDTLS_VERSION  commit $MBEDTLS_COMMIT  (https://github.com/Mbed-TLS/mbedtls; symbols prefixed _dbpro_)"
  echo "Xcode $(xcodebuild -version | sed -n 1p | cut -d' ' -f2), slices: macOS arm64 ($MACOS_DEPLOY), iOS arm64 ($IOS_DEPLOY), iOS simulator arm64 ($SIM_DEPLOY)"
  for slice in "${SLICES[@]}"; do
    echo "  ${slice%%|*}  sha256 $(shasum -a 256 "$WORK/slices/${slice%%|*}/libssh2_all.a" | cut -d' ' -f1)"
  done
} >"$SBOM"
info "$OUT"
info "$SBOM"
