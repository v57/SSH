import Foundation
import PostgresWire
import RedisWire
import SSHTunnel
import Testing
import WireKit

/// Key handling needs nothing. The tunnel tests need the `sshd` bastion from docker-compose.yml
/// (127.0.0.1:2222) and the key in `.testing/ssh`; or another sshd that takes that key and reaches Redis and
/// PostgreSQL on its own 127.0.0.1: `SSH_TEST_PORT=<port> SSH_TEST_USER=<user> SSH_TEST_SERVICES=local`.
/// `forwardsThroughThisMac` also needs that key in this Mac's `~/.ssh/authorized_keys` and Remote Login on.
@Suite(.serialized) struct SSHTunnelTests {
  static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
  static let keyURL = root.appendingPathComponent(".testing/ssh/id_ed25519")
  static let environment = ProcessInfo.processInfo.environment
  static let port = environment["SSH_TEST_PORT"].flatMap(Int.init) ?? 2222
  static let user = environment["SSH_TEST_USER"] ?? "tunnel"
  /// Where the services are, as the SSH server sees them.
  static let local = environment["SSH_TEST_SERVICES"] == "local"
  static let redisHost = local ? "127.0.0.1" : "redis"
  static let postgresHost = local ? "127.0.0.1" : "postgres"

  static func testKey() throws -> SSHKey { try SSHKey(importing: String(contentsOf: keyURL, encoding: .utf8)) }

  static var bastion: SSHServer {
    get throws { SSHServer(host: "127.0.0.1", port: port, user: user, key: try testKey()) }
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

  @Test func carriesRedisOverAChannel() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion)
    defer { tunnel.close() }
    #expect(tunnel.hostKeyFingerprint.hasPrefix("SHA256:"))
    let redis = try await RedisClient.connect(
      .init(host: Self.redisHost, port: 6379, database: 8, dialer: tunnel.dialer))
    #expect(try await redis.run("PING").string == "PONG")
    // A value bigger than one SSH window, and than what a channel buffers for the app, crosses intact.
    let big = String(repeating: "0123456789abcdef", count: 200_000)
    try await redis.run("SET", "tunnel:big", big)
    #expect(try await redis.run("GET", "tunnel:big").string == big)
    try await redis.run("DEL", "tunnel:big")
    await redis.close()
  }

  @Test func carriesSeveralConnectionsAtOnce() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion)
    defer { tunnel.close() }
    let config = PostgresClient.Config(
      host: Self.postgresHost, port: 5432, user: "postgres", password: "postgres", dialer: tunnel.dialer)
    try await withThrowingTaskGroup(of: Int64.self) { group in
      for i in 0..<6 {
        group.addTask {
          let client = try await PostgresClient.connect(config)
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

  @Test func reportsATargetThatRefuses() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion)
    defer { tunnel.close() }
    await #expect(throws: WireError.self) { try await tunnel.open(host: "127.0.0.1", port: 1) }
    // The tunnel stays usable.
    let redis = try await RedisClient.connect(.init(host: Self.redisHost, port: 6379, dialer: tunnel.dialer))
    #expect(try await redis.run("PING").string == "PONG")
    await redis.close()
  }

  @Test func closingTheTunnelEndsItsConnections() async throws {
    let tunnel = try await SSHTunnel.open(server: try Self.bastion)
    let redis = try await RedisClient.connect(.init(host: Self.redisHost, port: 6379, dialer: tunnel.dialer))
    #expect(try await redis.run("PING").string == "PONG")
    tunnel.close()
    await #expect(throws: (any Error).self) { try await redis.run("PING") }
    await #expect(throws: WireError.self) { try await tunnel.open(host: Self.redisHost, port: 6379) }
  }

  @Test(.enabled(if: !local, "needs the bastion's password login"))
  func logsInWithAPassword() async throws {
    let server = SSHServer(host: "127.0.0.1", port: Self.port, user: "tunnel", password: "tunnelpass")
    let tunnel = try await SSHTunnel.open(server: server)
    let redis = try await RedisClient.connect(.init(host: Self.redisHost, port: 6379, dialer: tunnel.dialer))
    #expect(try await redis.run("PING").string == "PONG")
    await redis.close()
    tunnel.close()
    #expect(tunnel.isAlive == false)
  }

  @Test func rejectsAWrongPassword() async throws {
    let server = SSHServer(host: "127.0.0.1", port: Self.port, user: Self.user, password: "wrong")
    await #expect(throws: SSHTunnelError.self) {
      try await SSHTunnel.open(server: server)
    }
  }

  @Test func refusesAChangedHostKey() async throws {
    var server = try Self.bastion
    server.knownFingerprint = "SHA256:not-the-real-one"
    do {
      _ = try await SSHTunnel.open(server: server)
      Issue.record("expected a host key error")
    } catch SSHTunnelError.hostKeyChanged(let expected, let actual) {
      #expect(expected == "SHA256:not-the-real-one")
      #expect(actual.hasPrefix("SHA256:"))
    }
  }

  @Test func reportsAnUnreachableServer() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 1, user: "nobody", password: "x")
    await #expect(throws: SSHTunnelError.self) {
      try await SSHTunnel.open(server: server, timeout: 3)
    }
  }

  // MARK: This Mac's own sshd

  @Test(.enabled(if: macKeyAuthorized, "add .testing/ssh/id_ed25519.pub to ~/.ssh/authorized_keys"))
  func forwardsThroughThisMac() async throws {
    let server = SSHServer(host: "127.0.0.1", port: 22, user: NSUserName(), key: try Self.testKey())
    let tunnel = try await SSHTunnel.open(server: server)
    defer { tunnel.close() }
    let redis = try await RedisClient.connect(.init(host: "127.0.0.1", port: 6379, dialer: tunnel.dialer))
    #expect(try await redis.run("PING").string == "PONG")
    await redis.close()
  }
}
