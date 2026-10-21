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

  // MARK: PEM keys from other tools

  /// Keys as `ssh-keygen -m PEM`/`-m PKCS8` (with explicit curve parameters, not a curve name) and `openssl` (SEC1
  /// after an `EC PARAMETERS` block, SEC1 with explicit parameters, PKCS#8) write them: each imports as the key
  /// `ssh-keygen -y` reads from the same file, and signs.
  @Test(arguments: [
    "ssh-keygen -q -t ecdsa -b 256 -m PEM -N '' -f key",
    "ssh-keygen -q -t ecdsa -b 384 -m PEM -N '' -f key",
    "ssh-keygen -q -t ecdsa -b 521 -m PEM -N '' -f key",
    "ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f key",
    "ssh-keygen -q -t ecdsa -b 256 -m PKCS8 -N '' -f key",
    "openssl ecparam -name prime256v1 -genkey -out key",
    "openssl ecparam -name secp384r1 -genkey -noout -out key",
    "openssl ecparam -name prime256v1 -genkey -noout -param_enc explicit -out key",
    "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key",
    "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out key",
    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key",
  ])
  func importsPEMKeysFromOtherTools(command: String) throws {
    let dir = try Self.run(command)
    defer { try? FileManager.default.removeItem(at: dir) }
    let key = try SSHKey(importing: String(contentsOf: dir.appendingPathComponent("key"), encoding: .utf8))
    let expected = try Self.output("ssh-keygen -y -f key", in: dir).split(separator: " ").prefix(2).joined(separator: " ")
    #expect(key.authorizedKeyLine.split(separator: " ").prefix(2).joined(separator: " ") == expected)
    #expect(try !key.sign(Array("hello".utf8)).isEmpty)
  }

  /// PKCS#8 Ed25519 (`openssl genpkey`), which `ssh-keygen` can't read: its public key from `openssl pkey` instead.
  @Test func importsPKCS8Ed25519Keys() throws {
    let dir = try Self.run("openssl genpkey -algorithm ED25519 -out key")
    defer { try? FileManager.default.removeItem(at: dir) }
    let key = try SSHKey(importing: String(contentsOf: dir.appendingPathComponent("key"), encoding: .utf8))
    // The SubjectPublicKeyInfo ends with the 32-byte public key.
    let spki = try Self.output("openssl pkey -in key -pubout -outform DER | base64", in: dir)
    let publicKey = Array(try #require(Data(base64Encoded: spki)).suffix(32))
    #expect(key.kind == .ed25519)
    #expect(try key.publicKeyBlob().suffix(32) == publicKey[...])
  }

  @Test func refusesASEC1KeyWhosePublicPointIsntItsOwn() throws {
    let dir = try Self.run("ssh-keygen -q -t ecdsa -b 256 -m PEM -N '' -f key")
    defer { try? FileManager.default.removeItem(at: dir) }
    let text = try String(contentsOf: dir.appendingPathComponent("key"), encoding: .utf8)
    let body = text.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
    // The public point is last: change its last byte.
    var der = try #require(Data(base64Encoded: body))
    der[der.count - 1] ^= 0x01
    let pem = "-----BEGIN EC PRIVATE KEY-----\n\(der.base64EncodedString())\n-----END EC PRIVATE KEY-----\n"
    #expect(throws: SSHKey.ImportError.self) { try SSHKey(importing: pem) }
  }

  /// Runs `command` through the shell in a new temporary folder, and returns the folder.
  static func run(_ command: String) throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    _ = try output(command, in: dir)
    return dir
  }

  static func output(_ command: String, in dir: URL) throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", command]
    process.currentDirectoryURL = dir
    // Homebrew's OpenSSL when there is one: macOS's LibreSSL can't make every kind of key.
    var environment = ProcessInfo.processInfo.environment
    environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + (environment["PATH"] ?? "/usr/bin:/bin")
    process.environment = environment
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    try #require(process.terminationStatus == 0, "\(command) failed")
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
