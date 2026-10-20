libssh2 1.11.1 (https://libssh2.org, BSD-3-Clause, see COPYING), unmodified `src/` and `include/` from the release
tarball, built from source on Windows with its WinCNG backend (Windows' own crypto): the other platforms link the
prebuilt Libssh2.xcframework (libssh2 + mbedTLS). Package.swift's Windows section swaps this target in.
