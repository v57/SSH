import CryptoKit
import Foundation
import SSHKit
import Testing

/// A key held outside the app (the Secure Enclave): the tunnel only sees its public blob and a signer.
struct ExternalKeyTests {
  @Test func anExternalKeySignsThroughItsSigner() throws {
    let inner = P256.Signing.PrivateKey()
    let software = try SSHKey(kind: .ecdsaP256, privateBytes: Array(inner.rawRepresentation))
    let external = SSHKey(kind: .ecdsaP256, publicKeyBlob: try software.publicKeyBlob(), comment: "enclave") {
      try software.sign($0)
    }
    #expect(external.privateBytes.isEmpty)
    #expect(try external.publicKeyBlob() == software.publicKeyBlob())
    #expect(external.fingerprint == software.fingerprint)
    #expect(external.authorizedKeyLine.hasPrefix("ecdsa-sha2-nistp256 "))
    #expect(external.authorizedKeyLine.hasSuffix(" enclave"))
    let signature = try external.sign(Array("challenge".utf8))
    #expect(!signature.isEmpty)
  }
}

/// A key that may have to ask the user first (`prepare`), against the test server.
@Suite(.enabled(if: TestServer.isUp)) struct PreparedKeyTests {
  private final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [String] = []
    func add(_ event: String) { lock.withLock { list.append(event) } }
    var all: [String] { lock.withLock { list } }
  }

  private struct NobodyConfirmed: Error {}

  private func server(
    _ events: Events, timeout: TimeInterval? = nil, prepare: @escaping @Sendable (Bool) throws -> Void
  ) throws -> SSHServer {
    let inner = try TestServer.testKey()
    let key = SSHKey(kind: inner.kind, publicKeyBlob: try inner.publicKeyBlob(), comment: "prepared", prepare: prepare) {
      events.add("sign")
      return try inner.sign($0)
    }
    return SSHServer(
      host: "127.0.0.1", port: TestServer.port, user: TestServer.user, key: key,
      trust: .ask { _ in
        events.add("host key")
        return true
      })
  }

  @Test func itRunsOnceTheHostKeyIsSettledAndBeforeSigning() async throws {
    let events = Events()
    let login = try server(events) { unattended in events.add("prepare \(unattended)") }
    let connection = try await SSHConnection.connect(server: login, timeout: 15)
    connection.close()
    #expect(events.all == ["host key", "prepare false", "sign"])
  }

  @Test func anUnattendedLoginSaysSo() async throws {
    let events = Events()
    var login = try server(events) { unattended in events.add("prepare \(unattended)") }
    login.unattended = true
    let connection = try await SSHConnection.connect(server: login, timeout: 15)
    connection.close()
    #expect(events.all.contains("prepare true"))
  }

  @Test func aRefusalEndsTheLoginWithoutSigning() async throws {
    let events = Events()
    let login = try server(events) { _ in throw NobodyConfirmed() }
    await #expect(throws: NobodyConfirmed.self) {
      _ = try await SSHConnection.connect(server: login, timeout: 15)
    }
    #expect(!events.all.contains("sign"))
  }

  @Test func timeSpentAnsweringDoesntCountAgainstTheLogin() async throws {
    let events = Events()
    let login = try server(events) { _ in Thread.sleep(forTimeInterval: 4) }
    let connection = try await SSHConnection.connect(server: login, timeout: 2)
    connection.close()
    #expect(events.all.contains("sign"))
  }
}
