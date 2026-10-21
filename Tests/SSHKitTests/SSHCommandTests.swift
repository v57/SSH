import Foundation
import Testing

@testable import SSHTunnel

/// Commands against the same SSH server as the SFTP tests (see `SSHTunnelTests`); skipped when nothing listens there.
@Suite(.serialized, .enabled(if: sshServerIsUp, "needs an sshd on SSH_TEST_PORT (see SSHTunnelTests)"))
struct SSHCommandTests {
  final class Output: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func append(_ chunk: Data) { lock.withLock { data.append(chunk) } }
    var text: String { lock.withLock { String(decoding: data, as: UTF8.self) } }
  }

  @Test func streamsOutputAndTheExitStatus() async throws {
    let output = Output()
    let command = SSHCommand(server: try SSHTunnelTests.bastion, command: "echo one; echo two >&2; exit 7")
    let status = try await command.run(timeout: 10) { output.append($0) }
    #expect(status == 7)
    #expect(output.text.contains("one"))
    #expect(output.text.contains("two"))
    #expect(command.hostKeyFingerprint.hasPrefix("SHA256:"))
  }

  @Test func stopHangsTheCommandUp() async throws {
    let output = Output()
    let marker = "ssh-command-test-\(UUID().uuidString.prefix(8))"
    let command = SSHCommand(server: try SSHTunnelTests.bastion, command: "echo started; sleep 30 # \(marker)")
    let started = Date()
    async let status = command.run(timeout: 10) { output.append($0) }
    while !output.text.contains("started"), Date().timeIntervalSince(started) < 10 {
      try await Task.sleep(for: .milliseconds(100))
    }
    command.stop()
    #expect(try await status == nil)
    #expect(Date().timeIntervalSince(started) < 10)
  }

  @Test func refusesAChangedHostKey() async throws {
    var server = try SSHTunnelTests.bastion
    server.knownFingerprint = "SHA256:not-the-key"
    let command = SSHCommand(server: server, command: "true")
    await #expect(throws: SSHTunnelError.self) { _ = try await command.run(timeout: 10) { _ in } }
  }
}
