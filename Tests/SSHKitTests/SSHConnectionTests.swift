import Foundation
import Testing

@testable import SSHKit

/// Commands over one connection, against the same SSH server as the SFTP tests (see `TestServer`); skipped when
/// nothing listens there.
@Suite(.serialized, .enabled(if: TestServer.isUp, "needs an sshd on SSH_TEST_PORT (see TestServer)"))
struct SSHConnectionTests {
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
