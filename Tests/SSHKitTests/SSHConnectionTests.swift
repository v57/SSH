import Foundation
import Testing

@testable import SSHKit

/// Commands over one connection, against the same SSH server as the SFTP tests (see `TestServer`); skipped when
/// nothing listens there.
@Suite(.serialized, .enabled(if: TestServer.isUp, "needs an sshd on SSH_TEST_PORT (see TestServer)"))
struct SSHConnectionTests {
  /// A fallback is trusted only with the host's key pinned (security audit M7): asking about whoever answers there
  /// would let anyone on the network answer for a `.local` name.
  @Test func triesTheFallbackAddressesWhenTheHostDoesntAnswer() async throws {
    let first = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    let fingerprint = first.hostKeyFingerprint
    first.close()
    var server = try TestServer.server
    server.fallbackHosts = [server.host]
    server.host = "unreachable.invalid"
    await #expect(throws: SSHTunnelError.hostKeyFromFallback(host: "unreachable.invalid", address: "127.0.0.1", fingerprint: fingerprint)) {
      try await SSHConnection.connect(server: server, timeout: 10).close()
    }
    server.trust = .pinned(fingerprint)
    let connection = try await SSHConnection.connect(server: server, timeout: 10)
    defer { connection.close() }
    #expect(connection.connectedHost == "127.0.0.1")
    #expect(try await connection.run("echo hi").status == 0)
  }

  @Test func keepsOutputAndErrorApartAndTheExitStatus() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let output = try await connection.run("printf 'one\\ntwo\\n'; echo oops >&2; exit 7")
    #expect(String(decoding: output.stdout, as: UTF8.self) == "one\ntwo\n")
    #expect(String(decoding: output.stderr, as: UTF8.self) == "oops\n")
    #expect(output.status == 7)
    #expect(connection.hostKeyFingerprint.hasPrefix("SHA256:"))
  }

  @Test func passesInputAndBinaryOutputThrough() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    // More than the channel's window both ways, with NULs and carriage returns a terminal would change.
    var input = Data()
    for index in 0..<(3 * 1024 * 1024) { input.append(UInt8(truncatingIfNeeded: index &* 31)) }
    input[10] = 0
    input[11] = 0x0D
    let output = try await connection.run("cat", input: input)
    #expect(output.status == 0)
    #expect(output.stdout == input)
  }

  @Test func aChannelTalksBackAndForth() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    // Answers each line while its input stays open, as git's services do.
    let channel = connection.open("while read line; do echo \"got $line\"; done; echo done >&2; exit 4")
    for word in ["one", "two"] {
      channel.write(Data("\(word)\n".utf8))
      let answer = try #require(try await channel.read())
      #expect(String(decoding: answer, as: UTF8.self) == "got \(word)\n")
    }
    channel.finishWriting()
    #expect(try await channel.read() == nil)
    let output = try await channel.finished()
    #expect(output.status == 4)
    #expect(String(decoding: output.stderr, as: UTF8.self) == "done\n")
  }

  @Test func aChannelEndsWhenItsCommandDoesWithItsInputOpen() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let channel = connection.open("echo nope >&2; exit 3")
    #expect(try await channel.read() == nil)
    let output = try await channel.finished()
    #expect(output.status == 3)
    #expect(String(decoding: output.stderr, as: UTF8.self) == "nope\n")
  }

  @Test func aSlowReaderGetsEverythingAChannelSends() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let channel = connection.open("head -c 20000000 /dev/zero")
    channel.finishWriting()
    var total = 0
    var reads = 0
    while let data = try await channel.read() {
      total += data.count
      reads += 1
      // Long enough for the channel to reach its limit and wait.
      if reads == 1 { try await Task.sleep(for: .seconds(1)) }
    }
    #expect(total == 20_000_000)
    #expect(try await channel.finished().status == 0)
    #expect(try await connection.run("echo still here").status == 0)
  }

  @Test func closingAChannelEndsItsRead() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let channel = connection.open("sleep 30")
    channel.close()
    await #expect(throws: (any Error).self) { _ = try await channel.read() }
    #expect(try await connection.run("echo still here").status == 0)
  }

  @Test func runsCommandsSideBySide() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let started = Date()
    let outputs = try await withThrowingTaskGroup(of: String.self) { group in
      for index in 0..<8 {
        group.addTask {
          let output = try await connection.run("sleep 1; echo \(index)")
          return String(decoding: output.stdout, as: UTF8.self)
        }
      }
      return try await group.reduce(into: [String]()) { $0.append($1) }
    }
    #expect(Set(outputs) == Set((0..<8).map { "\($0)\n" }))
    #expect(Date().timeIntervalSince(started) < 5)
  }

  @Test func reportsErrorOutputAsItArrives() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    defer { connection.close() }
    let seen = Seen()
    _ = try await connection.run("echo first >&2; sleep 1; echo second >&2") { seen.append($0) }
    #expect(seen.text == "first\nsecond\n")
    #expect(seen.chunks >= 2)
  }

  @Test func failsAfterClose() async throws {
    let connection = try await SSHConnection.connect(server: try TestServer.server, timeout: 10)
    connection.close()
    await #expect(throws: SSHTunnelError.self) { _ = try await connection.run("true") }
    #expect(!connection.isAlive)
  }

  final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private(set) var chunks = 0
    func append(_ chunk: Data) {
      lock.withLock {
        data.append(chunk)
        chunks += 1
      }
    }
    var text: String { lock.withLock { String(decoding: data, as: UTF8.self) } }
  }
}
