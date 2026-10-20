import Foundation
import Testing
import WireKit

@testable import SSHTunnel

/// SFTP against the same SSH server as the tunnel tests: the `sshd` bastion from docker-compose.yml
/// (127.0.0.1:2222, user "tunnel"), or any sshd with an SFTP subsystem that takes `.testing/ssh/id_ed25519`
/// (`SSH_TEST_PORT=<port> SSH_TEST_USER=<user> SSH_TEST_SERVICES=local`). Skipped when nothing listens there.
/// Files go in a new folder under /tmp on the server, removed at the end.
@Suite(.serialized, .enabled(if: sshServerIsUp, "needs an sshd on SSH_TEST_PORT (see SSHTunnelTests)"))
struct SFTPClientTests {
  /// The sshd's port as the server itself sees it, for logins through it as a jump host.
  static let portOnServer = SSHTunnelTests.local ? SSHTunnelTests.port : 22

  let root = "/tmp/sftp-tests-\(UUID().uuidString.prefix(8))"

  func connect(knownFingerprint: String? = nil) async throws -> SFTPClient {
    var server = try SSHTunnelTests.bastion
    server.knownFingerprint = knownFingerprint
    let client = try await SFTPClient.connect(server: server, timeout: 10)
    try await client.createDirectory(root)
    return client
  }

  func cleanUp(_ client: SFTPClient) async throws {
    // Depth first: files, then folders.
    func remove(_ path: String) async {
      for entry in (try? await client.list(path, followLinks: false)) ?? [] {
        if entry.isDirectory { await remove(entry.path) } else { try? await client.removeFile(entry.path) }
      }
      try? await client.removeDirectory(path)
    }
    await remove(root)
    #expect(try await client.stat(root) == nil)
    client.close()
  }

  @Test func writesReadsAndLists() async throws {
    let client = try await connect()
    #expect(client.hostKeyFingerprint.hasPrefix("SHA256:"))
    #expect(client.jumpHostKeyFingerprint == nil)
    let home = try await client.realPath(".")
    #expect(home.hasPrefix("/"))

    try await client.write(Data("hello world".utf8), to: "\(root)/docs/notes/a.txt", createParents: true)
    try await client.write(Data("b".utf8), to: "\(root)/docs/b.txt")
    #expect(try await client.read("\(root)/docs/notes/a.txt") == Data("hello world".utf8))

    let entries = try await client.list("\(root)/docs")
    #expect(entries.map(\.name) == ["b.txt", "notes"])
    #expect(entries.map(\.kind) == [.file, .directory])
    #expect(entries.map(\.path) == ["\(root)/docs/b.txt", "\(root)/docs/notes"])
    #expect(entries[0].size == 1 && entries[0].permissions == 0o644)
    #expect(entries[0].modified.map { abs($0.timeIntervalSinceNow) < 600 } == true)

    let info = try #require(try await client.stat("\(root)/docs/notes/a.txt"))
    #expect(info.size == 11 && info.kind == .file && info.name == "a.txt")
    #expect(try await client.stat("\(root)/missing") == nil)
    #expect(try await client.stat(root)?.isDirectory == true)

    // Writing again replaces the file, and leaves no temporary file behind.
    try await client.write(Data("new".utf8), to: "\(root)/docs/b.txt")
    #expect(try await client.read("\(root)/docs/b.txt") == Data("new".utf8))
    #expect(try await client.list("\(root)/docs").map(\.name) == ["b.txt", "notes"])
    try await cleanUp(client)
  }

  @Test func rangeReads() async throws {
    let client = try await connect()
    let path = "\(root)/f"
    try await client.write(Data("0123456789".utf8), to: path)
    #expect(try await client.read(path, offset: 2, length: 3) == Data("234".utf8))
    #expect(try await client.read(path, offset: 8, length: 12) == Data("89".utf8))
    #expect(try await client.read(path, offset: 12, length: 8) == Data())
    #expect(try await client.read(path, offset: 4) == Data("456789".utf8))
    #expect(try await client.read(path, offset: 0, length: 0) == Data())
    try await cleanUp(client)
  }

  @Test func bigFilesCrossIntact() async throws {
    let client = try await connect()
    // Several SFTP packets and SSH windows each way.
    var generator = SystemRandomNumberGenerator()
    let data = Data((0..<(3 * 1024 * 1024 + 123)).map { _ in UInt8.random(in: 0...255, using: &generator) })
    try await client.write(data, to: "\(root)/big.bin")
    #expect(try await client.stat("\(root)/big.bin")?.size == UInt64(data.count))
    #expect(try await client.read("\(root)/big.bin") == data)
    #expect(try await client.read("\(root)/big.bin", offset: 1_000_000, length: 700_000) == data[1_000_000..<1_700_000])
    try await cleanUp(client)
  }

  @Test func atomicWritesKeepPermissions() async throws {
    let client = try await connect()
    let path = "\(root)/script.sh"
    try await client.write(Data("#!/bin/sh\n".utf8), to: path, permissions: 0o700)
    #expect(try await client.stat(path)?.permissions == 0o700)
    try await client.write(Data("#!/bin/sh\necho hi\n".utf8), to: path)
    #expect(try await client.stat(path)?.permissions == 0o700)
    // In place, too.
    try await client.write(Data("x".utf8), to: path, atomic: false)
    #expect(try await client.read(path) == Data("x".utf8))
    try await cleanUp(client)
  }

  @Test func foldersRenamesAndRemoves() async throws {
    let client = try await connect()
    try await client.createDirectory("\(root)/x/y/z")
    try await client.createDirectory("\(root)/x/y")  // already there: fine
    #expect(try await client.stat("\(root)/x/y/z")?.isDirectory == true)
    try await client.write(Data("1".utf8), to: "\(root)/a/one", createParents: true)
    try await client.write(Data("2".utf8), to: "\(root)/a/two")
    try await client.write(Data("old".utf8), to: "\(root)/target")

    // A file replaces a file.
    try await client.rename("\(root)/a/one", to: "\(root)/target")
    #expect(try await client.read("\(root)/target") == Data("1".utf8))
    #expect(try await client.stat("\(root)/a/one") == nil)
    // A folder moves with its contents.
    try await client.rename("\(root)/a", to: "\(root)/x/y/a")
    #expect(try await client.read("\(root)/x/y/a/two") == Data("2".utf8))
    // Without replacing, an existing file stays.
    await #expect(throws: SFTPError.alreadyExists("\(root)/x/y/a/two")) {
      try await client.rename("\(root)/target", to: "\(root)/x/y/a/two", replacing: false)
    }

    try await client.removeFile("\(root)/x/y/a/two")
    try await client.removeDirectory("\(root)/x/y/a")
    #expect(try await client.list("\(root)/x/y").map(\.name) == ["z"])
    try await cleanUp(client)
  }

  @Test func errors() async throws {
    let client = try await connect()
    try await client.write(Data("x".utf8), to: "\(root)/file")
    try await client.createDirectory("\(root)/dir/sub")
    await #expect(throws: SFTPError.noSuchFile("\(root)/nope")) { try await client.read("\(root)/nope") }
    await #expect(throws: SFTPError.noSuchFile("\(root)/nope")) { try await client.list("\(root)/nope") }
    await #expect(throws: SFTPError.notADirectory("\(root)/file")) { try await client.list("\(root)/file") }
    await #expect(throws: SFTPError.isADirectory("\(root)/dir")) { try await client.read("\(root)/dir") }
    await #expect(throws: SFTPError.isADirectory("\(root)/dir")) { try await client.write(Data(), to: "\(root)/dir") }
    await #expect(throws: SFTPError.notADirectory("\(root)/file")) {
      try await client.write(Data(), to: "\(root)/file/inner", atomic: false)
    }
    await #expect(throws: SFTPError.notADirectory("\(root)/file")) {
      try await client.createDirectory("\(root)/file/inner")
    }
    await #expect(throws: SFTPError.alreadyExists("\(root)/file")) {
      try await client.createDirectory("\(root)/file", intermediate: false)
    }
    await #expect(throws: SFTPError.directoryNotEmpty("\(root)/dir")) { try await client.removeDirectory("\(root)/dir") }
    await #expect(throws: SFTPError.notADirectory("\(root)/file")) { try await client.removeDirectory("\(root)/file") }
    await #expect(throws: SFTPError.isADirectory("\(root)/dir")) { try await client.removeFile("\(root)/dir") }
    await #expect(throws: SFTPError.noSuchFile("\(root)/gone")) { try await client.removeFile("\(root)/gone") }
    await #expect(throws: SFTPError.noSuchFile("\(root)/missing")) {
      try await client.rename("\(root)/missing", to: "\(root)/z")
    }
    // A file never replaces a folder.
    await #expect(throws: SFTPError.alreadyExists("\(root)/dir")) { try await client.rename("\(root)/file", to: "\(root)/dir") }
    #expect(try await client.read("\(root)/file") == Data("x".utf8))
    try await cleanUp(client)
  }

  @Test func callsFromManyTasksAtOnce() async throws {
    let client = try await connect()
    try await withThrowingTaskGroup(of: Void.self) { group in
      for index in 0..<12 {
        group.addTask {
          let path = "\(root)/t\(index)"
          try await client.write(Data(repeating: UInt8(index), count: 10_000 * (index + 1)), to: path)
          #expect(try await client.read(path) == Data(repeating: UInt8(index), count: 10_000 * (index + 1)))
        }
      }
      try await group.waitForAll()
    }
    #expect(try await client.list(root).count == 12)
    try await cleanUp(client)
  }

  @Test func refusesAChangedHostKey() async throws {
    var server = try SSHTunnelTests.bastion
    server.knownFingerprint = "SHA256:not-the-real-one"
    do {
      _ = try await SFTPClient.connect(server: server)
      Issue.record("expected a host key error")
    } catch SSHTunnelError.hostKeyChanged(let expected, let actual) {
      #expect(expected == "SHA256:not-the-real-one")
      #expect(actual.hasPrefix("SHA256:"))
    }
  }

  @Test func closingFailsLaterCalls() async throws {
    let client = try await connect()
    let fingerprint = client.hostKeyFingerprint
    try await cleanUp(client)
    #expect(client.isAlive == false)
    await #expect(throws: SFTPError.closed) { try await client.stat("/") }
    // The remembered key lets the next login in.
    let again = try await connect(knownFingerprint: fingerprint)
    try await cleanUp(again)
  }

  // MARK: Jump hosts

  @Test func logsInThroughAJumpHost() async throws {
    // The server through itself: a login to it, a channel from it to its own sshd, a second login over that.
    let jump = try SSHTunnelTests.bastion
    let server = SSHServer(
      host: "127.0.0.1", port: Self.portOnServer, user: jump.user, key: jump.key)
    let client = try await SFTPClient.connect(server: server, through: jump, timeout: 10)
    #expect(client.jumpHostKeyFingerprint?.hasPrefix("SHA256:") == true)
    #expect(client.hostKeyFingerprint.hasPrefix("SHA256:"))
    try await client.createDirectory(root)
    let data = Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31) })
    try await client.write(data, to: "\(root)/through")
    #expect(try await client.read("\(root)/through") == data)
    try await cleanUp(client)
  }

  @Test func tunnelsThroughAJumpHost() async throws {
    let jump = try SSHTunnelTests.bastion
    let server = SSHServer(host: "127.0.0.1", port: Self.portOnServer, user: jump.user, key: jump.key)
    let tunnel = try await SSHTunnel.open(server: server, through: jump, timeout: 10)
    defer { tunnel.close() }
    #expect(tunnel.jumpHostKeyFingerprint?.hasPrefix("SHA256:") == true)
    // A service the server always has: its own sshd, which greets first.
    let channel = try await tunnel.open(host: "127.0.0.1", port: Self.portOnServer)
    let greeting = try await channel.receive()
    #expect(String(decoding: greeting, as: UTF8.self).hasPrefix("SSH-2.0-"))
    channel.close()
  }

  @Test func reportsAJumpHostThatCantReachTheServer() async throws {
    let jump = try SSHTunnelTests.bastion
    let server = SSHServer(host: "127.0.0.1", port: 1, user: jump.user, key: jump.key)
    await #expect(throws: SSHTunnelError.self) { try await SFTPClient.connect(server: server, through: jump, timeout: 5) }
  }
}

let sshServerIsUp: Bool = {
  guard FileManager.default.fileExists(atPath: SSHTunnelTests.keyURL.path) else { return false }
  guard let socket = try? Sockets.connect(host: "127.0.0.1", port: SSHTunnelTests.port, timeout: 1) else { return false }
  Sockets.close(socket)
  return true
}()

/// Path helpers; no server needed.
struct SFTPPathTests {
  @Test func parents() {
    #expect(SFTPClient.parent("/a/b/c") == "/a/b")
    #expect(SFTPClient.parent("/a") == "/")
    #expect(SFTPClient.parent("a/b/") == "a")
    #expect(SFTPClient.parent("a") == "")
    #expect(SFTPClient.join("/", "a") == "/a")
    #expect(SFTPClient.join("a", "b") == "a/b")
    #expect(SFTPClient.join("", "b") == "b")
    #expect(SFTPClient.name("/a/b.txt") == "b.txt")
  }
}
