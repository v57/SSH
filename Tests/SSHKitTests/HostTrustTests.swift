import Foundation
import Testing

@testable import SSHKit

/// The host key decision: nothing here needs a server but the last suite.
struct HostTrustTests {
  private func key(_ fingerprint: String, host: String = "prod.example.com", port: Int = 22) -> SSHHostKey {
    SSHHostKey(host: host, port: port, address: host, fingerprint: fingerprint, type: "ECDSA P-256")
  }

  private func server(_ trust: SSHHostTrust, host: String = "prod.example.com", port: Int = 22) -> SSHServer {
    SSHServer(host: host, port: port, user: "me", password: "secret", trust: trust)
  }

  @Test func anUnknownKeyIsRefusedWhenNobodyCanAnswer() {
    #expect(throws: SSHTunnelError.hostKeyUnverified(host: "prod.example.com", fingerprint: "SHA256:a")) {
      try server(.refuseUnknown).verify(key("SHA256:a"))
    }
  }

  @Test func aNoFromThePersonAskedStopsTheLogin() {
    #expect(throws: SSHTunnelError.hostKeyRejected(host: "prod.example.com", fingerprint: "SHA256:a")) {
      try server(.ask { _ in false }).verify(key("SHA256:a"))
    }
  }

  @Test func askingShowsTheKeyAndAYesGoesOn() throws {
    let seen = Seen()
    try server(.ask { seen.add($0.fingerprint); return true }).verify(key("SHA256:a"))
    #expect(seen.all == ["SHA256:a"])
  }

  @Test func aPinAcceptsOnlyItsOwnKey() throws {
    try server(.pinned("SHA256:a")).verify(key("SHA256:a"))
    #expect(throws: SSHTunnelError.hostKeyChanged(expected: "SHA256:a", actual: "SHA256:b")) {
      try server(.pinned("SHA256:a")).verify(key("SHA256:b"))
    }
  }

  @Test func aKnownKeyAsksNobodyAndAnEmptyOneDoesntCount() throws {
    let asked = SSHHostTrust.ask { _ in Issue.record("asked about a known key"); return false }
    try server(.known("SHA256:a", otherwise: asked)).verify(key("SHA256:a"))
    #expect(throws: SSHTunnelError.self) { try server(.known("", otherwise: .refuseUnknown)).verify(key("SHA256:a")) }
  }

  @Test func shippedKeysAskNobodyWhateverTheAppSays() throws {
    let asked = SSHHostTrust.ask { _ in Issue.record("asked about a shipped key"); return false }
    let ecdsa = "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"
    try server(asked, host: "GitHub.com").verify(key(ecdsa, host: "GitHub.com"))
    try server(.refuseUnknown, host: "github.com.").verify(key(ecdsa, host: "github.com."))
    try server(asked, host: "ssh.github.com", port: 443).verify(key(ecdsa, host: "ssh.github.com", port: 443))
    // gitlab.com's and bitbucket.org's ECDSA keys.
    try server(asked, host: "gitlab.com").verify(key("SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw", host: "gitlab.com"))
    try server(asked, host: "bitbucket.org").verify(key("SHA256:FC73VB6C4OQLSCrjEayhMp9UMxS97caD/Yyi2bhW/J0", host: "bitbucket.org"))
  }

  /// A saved pin and a yes both lose: a stranger answering for github.com is never let in.
  @Test func aStrangerAtAShippedHostIsRefusedEvenWithAYesOrAPin() {
    let stranger = key("SHA256:stranger", host: "github.com")
    for trust: SSHHostTrust in [.ask { _ in true }, .pinned("SHA256:stranger"), .refuseUnknown] {
      #expect(throws: SSHTunnelError.hostKeyNotPublished(host: "github.com", actual: "SHA256:stranger")) {
        try server(trust, host: "github.com").verify(stranger)
      }
    }
  }

  @Test func aShippedKeyHoldsOnlyForTheSitesOwnPort() throws {
    #expect(SSHKnownHosts.fingerprints(host: "github.com", port: 2222) == nil)
    #expect(SSHKnownHosts.fingerprints(host: "evil-github.com", port: 22) == nil)
    #expect(throws: SSHTunnelError.hostKeyUnverified(host: "github.com", fingerprint: "SHA256:x")) {
      try server(.refuseUnknown, host: "github.com", port: 2222).verify(key("SHA256:x", host: "github.com", port: 2222))
    }
  }

  final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []
    var all: [String] { lock.withLock { values } }
    func add(_ value: String) { lock.withLock { values.append(value) } }
  }
}

/// The hole S1 was about: credentials going to whoever answered. A signature is what a key login sends, so a counting
/// key shows whether one left. Against the test server.
@Suite(.enabled(if: TestServer.isUp, "needs an sshd on SSH_TEST_PORT (see TestServer)"))
struct NothingLeavesBeforeTheDecisionTests {
  private func countingKey(_ count: HostTrustTests.Seen) throws -> SSHKey {
    let inner = try TestServer.testKey()
    return SSHKey(kind: inner.kind, publicKeyBlob: try inner.publicKeyBlob()) { data in
      count.add("signed")
      return try inner.sign(data)
    }
  }

  @Test func aKeyIsntUsedForAnUnverifiedServer() async throws {
    for trust: SSHHostTrust in [.refuseUnknown, .ask { _ in false }, .pinned("SHA256:someone-else")] {
      let count = HostTrustTests.Seen()
      let server = SSHServer(host: "127.0.0.1", port: TestServer.port, user: TestServer.user, key: try countingKey(count), trust: trust)
      await #expect(throws: SSHTunnelError.self) { _ = try await SSHConnection.connect(server: server, timeout: 10) }
      #expect(count.all.isEmpty)
    }
  }

  @Test func aYesLetsTheKeySignAndShowsTheKeyFirst() async throws {
    let count = HostTrustTests.Seen()
    let shown = HostTrustTests.Seen()
    let trust = SSHHostTrust.ask { key in
      // Nothing has been signed by the time anyone is asked.
      shown.add("\(key.fingerprint) after \(count.all.count) signatures")
      return true
    }
    let server = SSHServer(host: "127.0.0.1", port: TestServer.port, user: TestServer.user, key: try countingKey(count), trust: trust)
    let connection = try await SSHConnection.connect(server: server, timeout: 10)
    defer { connection.close() }
    #expect(shown.all == ["\(connection.hostKeyFingerprint) after 0 signatures"])
    #expect(!count.all.isEmpty)
  }
}
