import Foundation
import Testing

@testable import SSHKit

/// A key's private bytes used to sit in a plain array, left in memory after the key was gone.
struct SecretBytesTests {
  @Test func theMemoryIsZeroWhenItsFreed() {
    final class Seen: @unchecked Sendable { var bytes: [UInt8]? }
    let seen = Seen()
    do {
      let secret = SSHSecretBytes([1, 2, 3, 4]) { buffer in
        seen.bytes = Array(buffer)
        buffer.deallocate()
      }
      #expect(secret.array == [1, 2, 3, 4])
    }
    #expect(seen.bytes == [0, 0, 0, 0])
  }

  @Test func aWorkingCopyCanBeCleared() {
    var bytes: [UInt8] = [9, 9, 9]
    SSHSecretBytes.wipe(&bytes)
    #expect(bytes == [0, 0, 0])
  }

  @Test func aKeyKeepsNoArrayOfItsPrivateBytes() {
    let key = SSHKey.generateEd25519(comment: "test")
    #expect(!key.privateBytes.isEmpty)
    for child in Mirror(reflecting: key).children { #expect(!(child.value is [UInt8])) }
  }

  @Test func aKeyStillSignsAndComparesThroughTheWipedStorage() throws {
    let key = SSHKey.generateEd25519(comment: "test")
    let again = try SSHKey(kind: .ed25519, privateBytes: key.privateBytes)
    #expect(try key.sign([1, 2, 3]).count == 64)
    #expect(key.isSameKey(as: again))
    #expect(!key.isSameKey(as: .generateEd25519(comment: "other")))
    let a = SSHServer(host: "h", user: "u", key: key, trust: .refuseUnknown)
    #expect(a == SSHServer(host: "h", user: "u", key: again, trust: .refuseUnknown))
    #expect(a != SSHServer(host: "h", user: "u", key: .generateEd25519(comment: "other"), trust: .refuseUnknown))
  }
}
