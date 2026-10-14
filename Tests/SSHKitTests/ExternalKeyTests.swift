import CryptoKit
import Foundation
import SSHTunnel
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
