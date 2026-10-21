import Foundation
import SSHKit
import Testing

/// Key handling: needs nothing but `ssh-keygen` (and the test server's key for the first test).
struct SSHKeyTests {
  @Test(.enabled(if: TestServer.hasKey, "needs .testing/ssh/id_ed25519 (see TestServer)"))
  func importsTheOpenSSHTestKey() throws {
    let key = try TestServer.testKey()
    #expect(key.kind == .ed25519)
    let pub = try String(contentsOf: TestServer.keyURL.appendingPathExtension("pub"), encoding: .utf8)
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
}
