import Foundation
import PostgresWire
import RedisWire
import SSHTunnel
import Testing

/// Key handling needs nothing. The tunnel tests need the `sshd` bastion from docker-compose.yml
/// (127.0.0.1:2222) and the key in `.testing/ssh`. `macSSHD` also needs that key in this Mac's
/// `~/.ssh/authorized_keys` and Remote Login on.
@Suite(.serialized) struct SSHTunnelTests {
  static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
  static let keyURL = root.appendingPathComponent(".testing/ssh/id_ed25519")

  static func testKey() throws -> SSHKey { try SSHKey(importing: String(contentsOf: keyURL, encoding: .utf8)) }

  static var bastion: SSHServer {
    get throws { SSHServer(host: "127.0.0.1", port: 2222, user: "tunnel", key: try testKey()) }
  }

  static var macKeyAuthorized: Bool {
    let authorized = (try? String(contentsOfFile: NSHomeDirectory() + "/.ssh/authorized_keys", encoding: .utf8)) ?? ""
    let pub = (try? String(contentsOf: keyURL.appendingPathExtension("pub"), encoding: .utf8)) ?? "-"
    guard let blob = pub.split(separator: " ").dropFirst().first, blob.count > 40 else { return false }
    return authorized.contains(blob)
  }

  // MARK: Keys

  @Test func importsTheOpenSSHTestKey() throws {
    let key = try Self.testKey()
    #expect(key.kind == .ed25519)
    let pub = try String(contentsOf: Self.keyURL.appendingPathExtension("pub"), encoding: .utf8)
    #expect(key.authorizedKeyLine == pub.trimmingCharacters(in: .whitespacesAndNewlines))
  }

  @Test func generatedKeysSurviveExport() throws {
    let key = SSHKey.generateEd25519(comment: "round trip")
    let again = try SSHKey(importing: key.openSSHPrivateKey)
    #expect(again.authorizedKeyLine == key.authorizedKeyLine)
    #expect(key.fingerprint.hasPrefix("SHA256:"))
  }

  @Test(arguments: ["ecdsa", "rsa"]) func importsKeysMadeBySSHKeygen(type: String) throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let path = dir.appendingPathComponent("key").path
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-q", "-t", type, "-N", "", "-C", "made by keygen", "-f", path] + (type == "rsa" ? ["-b", "2048"] : [])
    try process.run()
    process.waitUntilExit()
    let key = try SSHKey(importing: String(contentsOfFile: path, encoding: .utf8))
    let pub = try String(contentsOfFile: path + ".pub", encoding: .utf8)
    #expect(key.authorizedKeyLine == pub.trimmingCharacters(in: .whitespacesAndNewlines))
    #expect(try !key.sign(Array("hello".utf8)).isEmpty)
  }

  @Test func refusesPassphraseProtectedKeys() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let path = dir.appendingPathComponent("key").path
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-q", "-t", "ed25519", "-N", "secret", "-f", path]
    try process.run()
    process.waitUntilExit()
    #expect(throws: SSHKey.ImportError.self) { try SSHKey(importing: String(contentsOfFile: path, encoding: .utf8)) }
  }

  // MARK: Tunnels through the bastion

  @Test func forwardsToRedisWithAKey() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion, targetHost: "redis", targetPort: 6379)
    defer { tunnel.close() }
    #expect(tunnel.localPort > 0)
    #expect(tunnel.hostKeyFingerprint.hasPrefix("SHA256:"))
    let redis = try await RedisClient.connect(.init(host: "127.0.0.1", port: tunnel.localPort, database: 8))
    #expect(try await redis.run("PING").string == "PONG")
    // A value bigger than one SSH window crosses intact.
    let big = String(repeating: "0123456789abcdef", count: 200_000)
    try await redis.run("SET", "tunnel:big", big)
    #expect(try await redis.run("GET", "tunnel:big").string == big)
    try await redis.run("DEL", "tunnel:big")
    await redis.close()
  }

  @Test func carriesSeveralConnectionsAtOnce() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion, targetHost: "postgres", targetPort: 5432)
    defer { tunnel.close() }
    let port = tunnel.localPort
    try await withThrowingTaskGroup(of: Int64.self) { group in
      for i in 0..<6 {
        group.addTask {
          let client = try await PostgresClient.connect(
            .init(host: "127.0.0.1", port: port, user: "postgres", password: "postgres"))
          let result = try await client.execute("SELECT \(i)::bigint + 1, pg_sleep(0.1)")
          await client.close()
          return result.rows.first?.first?.intValue ?? -1
        }
      }
      var sum: Int64 = 0
      for try await value in group { sum += value }
      #expect(sum == (1...6).reduce(0, +))
    }
  }

  @Test func logsInWithAPassword() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 2222, user: "tunnel", password: "tunnelpass")
    let tunnel = try await SSHTunnel.open(server: server, targetHost: "redis", targetPort: 6379)
    let redis = try await RedisClient.connect(.init(host: "127.0.0.1", port: tunnel.localPort))
    #expect(try await redis.run("PING").string == "PONG")
    await redis.close()
    tunnel.close()
    #expect(tunnel.isAlive == false)
  }

  @Test func rejectsAWrongPassword() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 2222, user: "tunnel", password: "wrong")
    await #expect(throws: SSHTunnelError.self) {
      try await SSHTunnel.open(server: server, targetHost: "redis", targetPort: 6379)
    }
  }

  @Test func refusesAChangedHostKey() async throws {
    var server = try Self.bastion
    server.knownFingerprint = "SHA256:not-the-real-one"
    do {
      _ = try await SSHTunnel.open(server: server, targetHost: "redis", targetPort: 6379)
      Issue.record("expected a host key error")
    } catch SSHTunnelError.hostKeyChanged(let expected, let actual) {
      #expect(expected == "SHA256:not-the-real-one")
      #expect(actual.hasPrefix("SHA256:"))
    }
  }

  @Test func reportsAnUnreachableServer() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 1, user: "nobody", password: "x")
    await #expect(throws: SSHTunnelError.self) {
      try await SSHTunnel.open(server: server, targetHost: "redis", targetPort: 6379, timeout: 3)
    }
  }

  // MARK: This Mac's own sshd

  @Test(.enabled(if: macKeyAuthorized, "add .testing/ssh/id_ed25519.pub to ~/.ssh/authorized_keys"))
  func forwardsThroughThisMac() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 22, user: NSUserName(), key: try Self.testKey())
    let tunnel = try await SSHTunnel.open(server: server, targetHost: "127.0.0.1", targetPort: 6379)
    defer { tunnel.close() }
    let redis = try await RedisClient.connect(.init(host: "127.0.0.1", port: tunnel.localPort))
    #expect(try await redis.run("PING").string == "PONG")
    await redis.close()
  }
}
