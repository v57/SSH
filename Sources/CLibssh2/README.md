libssh2 1.11.1 (https://libssh2.org, BSD-3-Clause, see COPYING): `src/` and `include/` from the release tarball with the
security patches in `../../Patches/libssh2` applied (backports of upstream 97acf3d, 17626857 + fe907ca, 2dae302:
CVE-2026-55200, CVE-2026-55199, CVE-2025-15661), built from source on Windows (WinCNG) and Linux (OpenSSL). Apple
platforms link the prebuilt Libssh2.xcframework, which `Scripts/build-libssh2.sh` builds from the same tag and patches.
Package.swift's Windows and Linux section swaps this target in. A new patch goes into `Patches/libssh2` and is applied
here too (`patch -p1 -d Sources/CLibssh2 < Patches/libssh2/<patch>`).
