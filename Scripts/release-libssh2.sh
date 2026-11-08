#!/usr/bin/env bash
#
# release-libssh2.sh [TAG]: packs Binary/Libssh2.xcframework (from Scripts/build-libssh2.sh) for a GitHub release of
# v57/SSH, points Package.swift at it, and writes what Dev publishes. It publishes nothing itself and holds no token:
# Dev's in-process GitHub publish (the Git app's sign-in, GitHubKit) reads the request this script names on its
# `::publish github <file>` line, asks, and uploads. Run it from Dev (Workflows ▸ Publish libssh2 in SSH).
#
# TAG defaults to libssh2-<version>-p<number of Patches/libssh2/*.patch>, e.g. libssh2-1.11.1-p3.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FRAMEWORK=Binary/Libssh2.xcframework
SBOM=Binary/Libssh2.sbom.txt
ZIP=Binary/Libssh2.xcframework.zip
REQUEST=Binary/github-release.json
REPOSITORY=v57/SSH

[ -d "$FRAMEWORK" ] && [ -f "$SBOM" ] || { echo "::fail release no $FRAMEWORK: run Scripts/build-libssh2.sh"; exit 1; }
version=$(awk -F'"' '/define LIBSSH2_VERSION /{sub(/_DEV$/, "", $2); print $2; exit}' "$FRAMEWORK/macos-arm64/Headers/libssh2.h")
patches=$(find Patches/libssh2 -name '*.patch' | wc -l | tr -d ' ')
TAG="${1:-libssh2-$version-p$patches}"

rm -f "$ZIP"
(cd Binary && zip -qry -X "$(basename "$ZIP")" Libssh2.xcframework)
checksum=$(swift package compute-checksum "$ZIP")
url="https://github.com/$REPOSITORY/releases/download/$TAG/Libssh2.xcframework.zip"
sed -i '' -E -e "s|url: \"https://github.com/[^\"]*/Libssh2.xcframework.zip\"|url: \"$url\"|" \
  -e "s|checksum: \"[0-9a-f]{64}\"|checksum: \"$checksum\"|" Package.swift
grep -q "$checksum" Package.swift && grep -q "$url" Package.swift || { echo "::fail release Package.swift wasn't updated"; exit 1; }

json() { python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"; }
notes="libssh2 $version with $patches security patches (Patches/libssh2: CVE-2026-55200, CVE-2026-55199, CVE-2025-15661) on
Mbed TLS (symbols prefixed _dbpro_), for macOS, iOS and the iOS simulator (arm64), built by Scripts/build-libssh2.sh.
SSHKit links it as its Libssh2 binary target (SwiftPM checksum $checksum). Libssh2.sbom.txt lists the sources,
commits, patches and slices."
cat >"$REQUEST" <<JSON
{
  "format": 1,
  "repository": "$REPOSITORY",
  "tag": $(json "$TAG"),
  "title": $(json "libssh2 ${TAG#libssh2-}"),
  "notes": $(json "$notes"),
  "draft": false,
  "files": [
    {"path": $(json "$ROOT/$ZIP")},
    {"path": $(json "$ROOT/$SBOM")}
  ]
}
JSON
echo "$ZIP: $(du -h "$ZIP" | cut -f1), SwiftPM checksum $checksum"
echo "Package.swift now points at $url: commit it, then publish the release (tag $TAG on $REPOSITORY)."
echo "::publish github $ROOT/$REQUEST"
