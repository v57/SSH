# Libssh2

libssh2 itself, for apps that drive their own SSH sessions. Part of [SSH](../README.md); [SSHKit](SSHKit.md) is
built on it.

## Purpose

The `Libssh2` product is libssh2 1.11.1 with three security patches, as a C module named `CLibssh2`. Most apps
don't need it directly: [SSHKit](SSHKit.md) covers logins, commands, SFTP and jump hosts. Use it when an app runs its
own libssh2 session, such as a terminal that needs a pseudo-terminal channel it reads and writes itself. Shell's
terminals do this.

It is not a separate copy per app: SSHKit links the same target, and Database's `Libssh2` product re-exports this one.

## Getting started

```swift
// Package.swift
dependencies: [
  .package(url: "https://github.com/v57/SSH.git", branch: "main"),
],
targets: [
  .target(name: "MyApp", dependencies: [
    .product(name: "SSHKit", package: "SSH"),
    .product(name: "Libssh2", package: "SSH"),
  ]),
]
```

Log in through SSHKit, so the host key check and authentication stay the same as every other login, then use the
session with libssh2's own calls:

```swift
import CLibssh2
import SSHKit

let login = SSHLogin(server: server, jump: nil)   // server: an SSHServer, see SSHKit.md
do {
  try login.connect(timeout: 20)
  guard let session = login.session else { throw SSHTunnelError.closed }
  // The session is non-blocking: retry on LIBSSH2_ERROR_EAGAIN after login.waitSocket().
  _ = libssh2_session_last_errno(session)
} catch {
  // handle the error
}
login.teardown()
```

A session you make yourself with `libssh2_session_init_ex` should call `SSHAlgorithms.restrict(session)` before the
handshake and check the host key with `SSHServer.verify(_:)` before authenticating, as `SSHLogin` does.

## What's in it

- The module map exports `libssh2.h` and `libssh2_sftp.h` on every platform, and `libssh2_publickey.h` where libssh2
  builds from source (Linux, Windows).
- The patches in `Patches/libssh2` are backports of upstream fixes for three server-side bugs:
  - `0001`: a chacha20-poly1305 packet length past 35000 bytes is refused before it overflows (CVE-2026-55200).
  - `0002`: `EXT_INFO` stops at a bad entry and takes at most 1023 extensions (CVE-2026-55199).
  - `0003`: `sftp_symlink` reads its reply through a bounds-checked buffer (CVE-2025-15661).

## How it's built

### Apple platforms: the prebuilt xcframework

On macOS and iOS, `Libssh2` is a binary target. `Package.swift` points at `Libssh2.xcframework.zip` on this
repository's GitHub Releases (tag `libssh2-<version>-p<number of patches>`, for example `libssh2-1.11.1-p3`) with its
SwiftPM checksum. If `Binary/Libssh2.xcframework` exists (a local build; `Binary/` is gitignored), it is used instead.

`Scripts/build-libssh2.sh` builds it in one pass:

1. Clones libssh2 1.11.1 and Mbed TLS 3.6.7 at their tags and checks each against a pinned commit; a moved tag stops
   the build.
2. Applies `Patches/libssh2/*.patch`.
3. Builds one static archive per slice (libssh2 with the Mbed TLS crypto backend, plus Mbed TLS's libraries): macOS
   arm64 (14.0), iOS arm64 (13.0) and iOS simulator arm64 (15.0). It fails if an archive references OpenSSL.
4. Renames every Mbed TLS and PSA symbol with a `_dbpro_` prefix and leaves out the Mbed TLS headers, so an app can
   also link another Mbed TLS (DuckDB bundles one) without clashes.
5. Writes `Binary/Libssh2.xcframework` and `Binary/Libssh2.sbom.txt` (versions, commits, the SHA-256 of each patch and
   each slice).

It needs Xcode, cmake and llvm-objcopy (`brew install cmake llvm`, or `OBJCOPY=<path>`), git and the network.
`LIBSSH2_BUILD_DIR` moves the scratch folder (default `.build/libssh2`). `Scripts/build-libssh2.sh clean` removes the
scratch folder and the output. Check libssh2's and Mbed TLS's security advisories before each rebuild; the script's
header lists where.

`Scripts/release-libssh2.sh [TAG]` zips the xcframework, computes the SwiftPM checksum, rewrites the URL and checksum
in `Package.swift`, and writes `Binary/github-release.json`, a release request for the zip and the SBOM. It publishes
nothing itself and holds no token: Dev's "Publish libssh2" workflow (`.dev/workflows/libssh2.json`) runs it and
uploads the release. Commit the `Package.swift` change with the release.

There are no x86_64 slices, so Intel Macs and the x86_64 simulator aren't covered.

### Linux and Windows: from source

`Sources/CLibssh2` holds libssh2 1.11.1's `src/` and `include/` from the release tarball with the same patches
applied. On Linux and Windows `Package.swift` replaces the binary target with this C target:

- Linux: the OpenSSL backend, linking the system's `libssl` and `libcrypto` (`apt install libssl-dev`). This copy is
  used rather than the distribution's libssh2, which may be older (Ubuntu 24.04 ships 1.11.0, without
  `libssh2_sftp_posix_rename_ex`).
- Windows: the WinCNG backend with ECDSA, linking `bcrypt`, `crypt32` and `ws2_32`. OpenSSH 10 servers offer no
  finite-field Diffie-Hellman, so ECDSA key exchange is needed to reach them.

A new patch goes into `Patches/libssh2` and is applied to `Sources/CLibssh2` too
(`patch -p1 -d Sources/CLibssh2 < Patches/libssh2/<patch>`), then the xcframework is rebuilt and released.

## Platform notes

- **macOS, iOS / iPadOS**: the prebuilt xcframework, arm64 only. Its Mbed TLS backend has no Ed25519 host keys:
  servers need an ECDSA or RSA host key.
- **Linux**: built from source with OpenSSL; tested on Ubuntu 24.04.
- **Windows**: built from source with WinCNG; tested on a Windows VM against an OpenSSH sshd.
- **Android**: not yet.

## Testing

libssh2 has no tests of its own here. SSHKit's suites exercise it (see [SSHKit's testing section](SSHKit.md#testing)),
including `HostileServerTests`, which sends the packets of the patched bugs from a fake server and runs on Apple
platforms without an sshd:

```bash
swift test --filter HostileServerTests
```
