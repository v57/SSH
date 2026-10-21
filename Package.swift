// swift-tools-version: 6.2

import Foundation
import PackageDescription

let concurrency: [SwiftSetting] = [.enableUpcomingFeature("ApproachableConcurrency")]

// libssh2 + mbedTLS (module CLibssh2), prebuilt by Database's Scripts/build-libssh2.sh and published on Database's
// GitHub Releases. Binary/Libssh2.xcframework (not in git) is used instead when it's there.
let libssh2: Target = {
  let path = "Binary/Libssh2.xcframework"
  return FileManager.default.fileExists(atPath: Context.packageDirectory + "/" + path)
    ? .binaryTarget(name: "Libssh2", path: path)
    : .binaryTarget(
      name: "Libssh2",
      url: "https://github.com/v57/Database/releases/download/libssh2-1.11.1/Libssh2.xcframework.zip",
      checksum: "b855ccebd64a0434cb1d59b1c1376676682a3fc48fde829b837881307abcea98")
}()

let package = Package(
  name: "SSH",
  platforms: [.macOS(.v14), .iOS(.v17)],
  products: [
    // Logins, keys, SFTP, commands, jump hosts and the socket layer, on libssh2.
    .library(name: "SSHKit", targets: ["SSHKit"]),
    // libssh2 + mbedTLS itself, for apps that drive their own sessions (Shell's terminals).
    .library(name: "Libssh2", targets: ["Libssh2"]),
  ],
  targets: [
    libssh2,
    .target(name: "SSHKit", dependencies: ["Libssh2"], swiftSettings: concurrency),
    .testTarget(name: "SSHKitTests", dependencies: ["SSHKit"], swiftSettings: concurrency),
  ]
)

#if os(Windows) || os(Linux)
/// Another v57 repository: GitHub's main branch, or the checkout next to this one with `V57_LOCAL=1`.
func v57(_ name: String) -> Package.Dependency {
  Context.environment["V57_LOCAL"] == nil
    ? .package(url: "https://github.com/v57/\(name).git", branch: "main") : .package(path: "../\(name)")
}
// Off Apple platforms CryptoKit and os are v57/SwiftUI's stand-ins, RSA is swift-crypto's _CryptoExtras
// (Security.framework's on Apple platforms), and libssh2 builds from source (Sources/CLibssh2) with the platform's
// crypto (WinCNG on Windows) in place of the prebuilt xcframework.
package.dependencies += [
  v57("SwiftUI"), .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
]
package.targets.removeAll { $0.name == "Libssh2" }
package.targets.append(
  .target(
    name: "CLibssh2", path: "Sources/CLibssh2",
    exclude: [
      "COPYING", "README.md",
      // crypto.c includes the backend's file, agent.c the Windows agents'.
      "src/openssl.c", "src/libgcrypt.c", "src/mbedtls.c", "src/os400qc3.c", "src/wincng.c", "src/agent_win.c",
    ],
    sources: ["src"],
    // ECDSA (ecdh-sha2-nistp* key exchange, ECDSA host keys) needs Windows 10's BCrypt: OpenSSH 10 servers offer
    // no finite-field Diffie-Hellman, so without it they can't be reached.
    cSettings: [
      .define("LIBSSH2_WINCNG"), .define("LIBSSH2_ECDSA_WINCNG"), .define("LIBSSH2_LIBRARY"), .unsafeFlags(["-w"]),
    ]))
package.products.removeAll { $0.name == "Libssh2" }
package.products.append(.library(name: "Libssh2", targets: ["CLibssh2"]))
for target in package.targets where target.name == "SSHKit" || target.name == "SSHKitTests" {
  target.dependencies.removeAll { "\($0)".contains("Libssh2") }
  if target.name == "SSHKit" {
    target.dependencies += [
      "CLibssh2", .product(name: "CryptoKit", package: "SwiftUI"),
      .product(name: "_CryptoExtras", package: "swift-crypto"),
      .product(name: "SwiftUIPortability", package: "SwiftUI"), .product(name: "os", package: "SwiftUI"),
    ]
  }
  // Apple's Foundation extras (`URL.applicationSupportDirectory`, …) come from SwiftUIPortability: imported
  // everywhere, as Foundation is on Apple platforms.
  target.swiftSettings = (target.swiftSettings ?? []) + [
    .unsafeFlags(["SwiftUIPortability"].flatMap { ["-Xfrontend", "-import-module", "-Xfrontend", $0] })
  ]
}
#endif
