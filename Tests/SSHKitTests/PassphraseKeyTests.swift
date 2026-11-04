import Foundation
import Testing

@testable import SSHKit

/// Keys behind a passphrase used to be refused with advice to take the passphrase off. Each key here is written by
/// `ssh-keygen` or `openssl` and must open as the key `ssh-keygen -y` reads from the same file.
struct PassphraseKeyTests {
  private static let passphrase = "correct horse"

  private func isError(_ expected: SSHKey.ImportError) -> (any Error) -> Bool {
    { error in
      switch (error as? SSHKey.ImportError, expected) {
      case (.needsPassphrase, .needsPassphrase), (.wrongPassphrase, .wrongPassphrase): true
      case (.unsupportedEncryption, .unsupportedEncryption): true
      default: false
      }
    }
  }

  private func text(_ dir: URL) throws -> String {
    try String(contentsOf: dir.appendingPathComponent("key"), encoding: .utf8)
  }

  private func expectOpens(_ command: String) throws {
    let dir = try SSHKeyTests.run(command)
    defer { try? FileManager.default.removeItem(at: dir) }
    let key = try SSHKey(importing: text(dir), passphrase: Self.passphrase)
    let expected = try SSHKeyTests.output("ssh-keygen -y -P '\(Self.passphrase)' -f key", in: dir)
      .split(separator: " ").prefix(2).joined(separator: " ")
    #expect(key.authorizedKeyLine.split(separator: " ").prefix(2).joined(separator: " ") == expected)
    #expect(try !key.sign(Array("hello".utf8)).isEmpty)
    #expect { try SSHKey(importing: text(dir)) } throws: { isError(.needsPassphrase)($0) }
    #expect { try SSHKey(importing: text(dir), passphrase: "") } throws: { isError(.needsPassphrase)($0) }
    #expect { try SSHKey(importing: text(dir), passphrase: "battery staple") } throws: { isError(.wrongPassphrase)($0) }
  }

  @Test(arguments: [
    "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
  ])
  func opensEachCipherOfOpenSSHsFormat(cipher: String) throws {
    try expectOpens("ssh-keygen -q -t ed25519 -a 2 -Z \(cipher) -N '\(Self.passphrase)' -f key")
  }

  @Test(arguments: ["ed25519", "ecdsa -b 256", "ecdsa -b 384", "ecdsa -b 521", "rsa -b 2048"])
  func opensEachKeyTypeWithSshKeygensDefaults(type: String) throws {
    try expectOpens("ssh-keygen -q -t \(type) -N '\(Self.passphrase)' -f key")
  }

  @Test(arguments: [
    "openssl genrsa -aes128 -traditional -passout pass:'correct horse' -out key 2048",
    "openssl genrsa -aes256 -traditional -passout pass:'correct horse' -out key 2048",
    "openssl ecparam -name prime256v1 -genkey -noout | openssl ec -aes-128-cbc -passout pass:'correct horse' -out key",
    "openssl ecparam -name secp384r1 -genkey -noout | openssl ec -aes-256-cbc -passout pass:'correct horse' -out key",
    "ssh-keygen -q -t rsa -b 2048 -m PEM -N 'correct horse' -f key",
  ])
  func opensThePEMFormat(command: String) throws {
    try expectOpens(command)
  }

  @Test func namesWhatItCantOpen() throws {
    let dir = try SSHKeyTests.run("ssh-keygen -q -t ed25519 -a 2 -Z chacha20-poly1305@openssh.com -N 'correct horse' -f key")
    defer { try? FileManager.default.removeItem(at: dir) }
    #expect { try SSHKey(importing: text(dir), passphrase: Self.passphrase) } throws: { error in
      isError(.unsupportedEncryption(""))(error) && (error as? LocalizedError)?.errorDescription?.contains("chacha20") == true
    }
    let pkcs8 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
    #expect { try SSHKey(importing: pkcs8, passphrase: Self.passphrase) } throws: { isError(.unsupportedEncryption(""))($0) }
  }

  @Test func theMessageNoLongerSaysToRemoveThePassphrase() {
    let message = SSHKey.ImportError.needsPassphrase.errorDescription ?? ""
    #expect(!message.lowercased().contains("remove"))
    #expect(message.contains("passphrase"))
  }

  /// OpenBSD's regress test for bcrypt_pbkdf (also py-bcrypt's).
  @Test func bcryptPBKDFMatchesAKnownVector() {
    let key = SSHBcryptPBKDF.derive(password: Array("password".utf8), salt: Array("salt".utf8), count: 32, rounds: 4)
    let hex = key.map { String(format: "%02x", $0) }.joined()
    #expect(hex == "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9")
  }

  @Test func aFileAskingForAbsurdRoundsIsRefused() throws {
    var options = SSHWire.Writer()
    SSHWire.string(&options, [1, 2, 3, 4])
    options.writeBE(UInt32.max)
    #expect(throws: SSHKey.ImportError.self) {
      try SSHKeyDecryption.openSSH(
        cipher: "aes256-ctr", kdf: "bcrypt", kdfOptions: options.bytes, encrypted: [UInt8](repeating: 0, count: 16), tag: [],
        passphrase: "x")
    }
  }
}
