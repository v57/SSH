import Foundation
import Testing

@testable import SSHKit

/// What SSHKit says goes on screen under an app's own titles ("Couldn’t Open …"), which use typographic apostrophes:
/// a reason with straight ones beside them read as two styles (Code C-002).
struct ErrorTextTests {
  @Test func messagesUseTypographicApostrophes() {
    let errors: [any LocalizedError] = [
      SSHTunnelError.connectFailed(SSHLogin.describe(.hostNotFound("mac"), host: "mac")),
      SSHTunnelError.handshakeFailed("x"),
      SSHTunnelError.hostKeyChanged(expected: "a", actual: "b"),
      SSHTunnelError.hostKeyUnverified(host: "mac", fingerprint: "f"),
      SSHTunnelError.hostKeyRejected(host: "mac", fingerprint: "f"),
      SSHTunnelError.hostKeyFromFallback(host: "mac", address: "10.0.0.2", fingerprint: "f"),
      SSHTunnelError.hostKeyNotPublished(host: "github.com", actual: "f"),
      SSHTunnelError.authenticationFailed(methods: "publickey"),
      SSHTunnelError.forwardFailed("x"),
      SSHTunnelError.closed,
      SFTPError.noSuchFile("/a"), SFTPError.permissionDenied("/a"), SFTPError.directoryNotEmpty("/a"),
      SFTPError.notADirectory("/a"), SFTPError.unsupported("x"), SFTPError.closed,
      SSHKey.ImportError.unrecognized, SSHKey.ImportError.wrongPassphrase,
      SSHKey.ImportError.unsupportedEncryption("3DES"), SSHKey.ImportError.unsupportedType("This curve’s"),
    ]
    for error in errors {
      let text = error.errorDescription ?? ""
      #expect(!text.contains("'"), "\(text)")
    }
  }

  /// The reasons thrown with a detail of SSHKit's own, read in the sources: a test can't reach each `throw`.
  @Test func thrownDetailsUseTypographicApostrophes() throws {
    let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().appendingPathComponent("Sources/SSHKit")
    let names = try FileManager.default.contentsOfDirectory(atPath: sources.path).filter { $0.hasSuffix(".swift") }
    #expect(!names.isEmpty)
    // A straight apostrophe between letters inside a string literal of a throw or a description.
    let pattern = try Regex(#"(throw|case \.|^\s*")[^/]*"[^"]*[A-Za-z)]'[a-z]"#)
    for name in names {
      let text = try String(contentsOf: sources.appendingPathComponent(name), encoding: .utf8)
      for line in text.split(separator: "\n") where !line.trimmingCharacters(in: .whitespaces).hasPrefix("//") {
        #expect(line.firstMatch(of: pattern) == nil, "\(name): \(line)")
      }
    }
  }
}
