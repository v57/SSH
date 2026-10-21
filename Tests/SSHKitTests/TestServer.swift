import Foundation
import SSHKit

/// The SSH server the login tests use: any sshd with an SFTP subsystem and TCP forwarding on that takes
/// `.testing/ssh/id_ed25519` (`ssh-keygen -t ed25519 -N "" -f .testing/ssh/id_ed25519`, or `SSH_TEST_KEY=<path>`), at
/// 127.0.0.1:`SSH_TEST_PORT` (2222) as `SSH_TEST_USER` ("tunnel"): Database's docker-compose bastion, or a user-level
/// sshd. libssh2 here is mbedTLS, so the sshd needs an ECDSA or RSA host key. Suites skip when nothing listens there.
enum TestServer {
  static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
  static let environment = ProcessInfo.processInfo.environment
  static let keyURL = environment["SSH_TEST_KEY"].map { URL(fileURLWithPath: $0) }
    ?? root.appendingPathComponent(".testing/ssh/id_ed25519")
  static let port = environment["SSH_TEST_PORT"].flatMap(Int.init) ?? 2222
  static let user = environment["SSH_TEST_USER"] ?? "tunnel"
  /// The sshd's port as the server itself sees it, for logins through it as a jump host (the bastion's container
  /// listens on 22).
  static let portOnServer = environment["SSH_TEST_SERVICES"] == "local" ? port : 22

  static var hasKey: Bool { FileManager.default.fileExists(atPath: keyURL.path) }

  static func testKey() throws -> SSHKey { try SSHKey(importing: String(contentsOf: keyURL, encoding: .utf8)) }

  static var server: SSHServer {
    get throws { SSHServer(host: "127.0.0.1", port: port, user: user, key: try testKey()) }
  }

  static let isUp: Bool = {
    guard hasKey else { return false }
    guard let socket = try? Sockets.connect(host: "127.0.0.1", port: port, timeout: 1) else { return false }
    Sockets.close(socket)
    return true
  }()
}
