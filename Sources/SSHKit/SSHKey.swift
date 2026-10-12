import CryptoKit
import Foundation
import Security
import WireKit

/// A private key for SSH public-key login. Signing happens in Swift (CryptoKit /
/// Security), and libssh2 gets the signature through its sign callback.
public struct SSHKey: Sendable {
  public enum Kind: String, Sendable, Codable {
    case ed25519 = "ssh-ed25519"
    case ecdsaP256 = "ecdsa-sha2-nistp256"
    case ecdsaP384 = "ecdsa-sha2-nistp384"
    case ecdsaP521 = "ecdsa-sha2-nistp521"
    case rsa = "ssh-rsa"

    public var label: String {
      switch self {
      case .ed25519: "Ed25519"
      case .ecdsaP256: "ECDSA P-256"
      case .ecdsaP384: "ECDSA P-384"
      case .ecdsaP521: "ECDSA P-521"
      case .rsa: "RSA"
      }
    }
  }

  public let kind: Kind
  /// Raw private key material: the 32-byte seed for Ed25519, the scalar for ECDSA,
  /// PKCS#1 DER for RSA.
  public let privateBytes: [UInt8]
  public var comment: String

  public init(kind: Kind, privateBytes: [UInt8], comment: String = "") throws {
    self.kind = kind
    self.privateBytes = privateBytes
    self.comment = comment
    _ = try publicKeyBlob()  // validates the material
  }

  /// A new Ed25519 key.
  public static func generateEd25519(comment: String) -> SSHKey {
    let key = Curve25519.Signing.PrivateKey()
    return try! SSHKey(kind: .ed25519, privateBytes: Array(key.rawRepresentation), comment: comment)
  }

  // MARK: Public key

  public func publicKeyBlob() throws -> [UInt8] {
    var w = ByteWriter()
    SSHWire.string(&w, Array(kind.rawValue.utf8))
    switch kind {
    case .ed25519:
      let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateBytes)
      SSHWire.string(&w, Array(key.publicKey.rawRepresentation))
    case .ecdsaP256:
      SSHWire.string(&w, Array("nistp256".utf8))
      SSHWire.string(&w, Array(try P256.Signing.PrivateKey(rawRepresentation: privateBytes).publicKey.x963Representation))
    case .ecdsaP384:
      SSHWire.string(&w, Array("nistp384".utf8))
      SSHWire.string(&w, Array(try P384.Signing.PrivateKey(rawRepresentation: privateBytes).publicKey.x963Representation))
    case .ecdsaP521:
      SSHWire.string(&w, Array("nistp521".utf8))
      SSHWire.string(&w, Array(try P521.Signing.PrivateKey(rawRepresentation: privateBytes).publicKey.x963Representation))
    case .rsa:
      let (n, e) = try SSHRSA.publicNumbers(pkcs1: privateBytes)
      SSHWire.mpint(&w, e)
      SSHWire.mpint(&w, n)
    }
    return w.bytes
  }

  /// The line to paste into `~/.ssh/authorized_keys`.
  public var authorizedKeyLine: String {
    let blob = (try? publicKeyBlob()) ?? []
    let line = "\(kind.rawValue) \(Data(blob).base64EncodedString())"
    return comment.isEmpty ? line : line + " " + comment
  }

  /// `SHA256:…`, as `ssh-keygen -l` prints it.
  public var fingerprint: String {
    let digest = Digest.sha256((try? publicKeyBlob()) ?? [])
    return "SHA256:" + Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
  }

  // MARK: Signing

  /// The signature body libssh2 expects from its sign callback (no algorithm name).
  public func sign(_ data: [UInt8]) throws -> [UInt8] {
    switch kind {
    case .ed25519:
      return Array(try Curve25519.Signing.PrivateKey(rawRepresentation: privateBytes).signature(for: data))
    case .ecdsaP256:
      let raw = try P256.Signing.PrivateKey(rawRepresentation: privateBytes).signature(for: data).rawRepresentation
      return Self.ecdsaBlob(Array(raw))
    case .ecdsaP384:
      let raw = try P384.Signing.PrivateKey(rawRepresentation: privateBytes).signature(for: data).rawRepresentation
      return Self.ecdsaBlob(Array(raw))
    case .ecdsaP521:
      let raw = try P521.Signing.PrivateKey(rawRepresentation: privateBytes).signature(for: data).rawRepresentation
      return Self.ecdsaBlob(Array(raw))
    case .rsa:
      return try SSHRSA.signSHA256(pkcs1: privateBytes, data: data)
    }
  }

  static func ecdsaBlob(_ raw: [UInt8]) -> [UInt8] {
    let half = raw.count / 2
    var w = ByteWriter()
    SSHWire.mpint(&w, Array(raw[..<half]))
    SSHWire.mpint(&w, Array(raw[half...]))
    return w.bytes
  }

  // MARK: Import and export

  public enum ImportError: Error, LocalizedError {
    case unrecognized
    case encrypted
    case unsupportedType(String)

    public var errorDescription: String? {
      switch self {
      case .unrecognized: "This doesn't look like an SSH private key."
      case .encrypted:
        "This key is protected by a passphrase, which Database Pro can't read yet. Remove the passphrase with `ssh-keygen -p -f <key>`, or create a new key in Database Pro."
      case .unsupportedType(let type): "\(type) keys aren't supported. Use an Ed25519, ECDSA or RSA key."
      }
    }
  }

  /// Reads an OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) or PEM private key.
  public init(importing text: String) throws {
    let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
    guard let begin = lines.first(where: { $0.hasPrefix("-----BEGIN ") }) else { throw ImportError.unrecognized }
    if text.contains("Proc-Type: 4,ENCRYPTED") || begin.contains("ENCRYPTED") { throw ImportError.encrypted }
    let body = lines.filter { !$0.hasPrefix("-----") && !$0.contains(":") }.joined()
    guard let der = Data(base64Encoded: body).map({ [UInt8]($0) }) else { throw ImportError.unrecognized }
    switch begin {
    case "-----BEGIN OPENSSH PRIVATE KEY-----": self = try Self.parseOpenSSH(der)
    case "-----BEGIN RSA PRIVATE KEY-----": self = try SSHKey(kind: .rsa, privateBytes: der)
    case "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----":
      let pem = text
      if let key = try? P256.Signing.PrivateKey(pemRepresentation: pem) {
        self = try SSHKey(kind: .ecdsaP256, privateBytes: Array(key.rawRepresentation))
      } else if let key = try? P384.Signing.PrivateKey(pemRepresentation: pem) {
        self = try SSHKey(kind: .ecdsaP384, privateBytes: Array(key.rawRepresentation))
      } else if let key = try? P521.Signing.PrivateKey(pemRepresentation: pem) {
        self = try SSHKey(kind: .ecdsaP521, privateBytes: Array(key.rawRepresentation))
      } else if der.count == 48, der.suffix(34).prefix(2) == [0x04, 0x20] {
        // PKCS#8 Ed25519: the last 32 bytes are the seed.
        self = try SSHKey(kind: .ed25519, privateBytes: Array(der.suffix(32)))
      } else {
        throw ImportError.unsupportedType("This PKCS#8")
      }
    default:
      throw ImportError.unrecognized
    }
  }

  static func parseOpenSSH(_ der: [UInt8]) throws -> SSHKey {
    let magic = Array("openssh-key-v1".utf8) + [0]
    guard der.starts(with: magic) else { throw ImportError.unrecognized }
    var r = ByteReader(der, offset: magic.count)
    let cipher = String(decoding: try SSHWire.readString(&r), as: UTF8.self)
    _ = try SSHWire.readString(&r)  // kdf name
    _ = try SSHWire.readString(&r)  // kdf options
    guard cipher == "none" else { throw ImportError.encrypted }
    let count = try r.readBE(UInt32.self)
    guard count >= 1 else { throw ImportError.unrecognized }
    for _ in 0..<count { _ = try SSHWire.readString(&r) }
    var p = ByteReader(try SSHWire.readString(&r))
    let check1 = try p.readBE(UInt32.self)
    let check2 = try p.readBE(UInt32.self)
    guard check1 == check2 else { throw ImportError.encrypted }
    let type = String(decoding: try SSHWire.readString(&p), as: UTF8.self)
    switch type {
    case "ssh-ed25519":
      _ = try SSHWire.readString(&p)
      let secret = try SSHWire.readString(&p)
      let comment = String(decoding: try SSHWire.readString(&p), as: UTF8.self)
      return try SSHKey(kind: .ed25519, privateBytes: Array(secret.prefix(32)), comment: comment)
    case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
      _ = try SSHWire.readString(&p)  // curve
      _ = try SSHWire.readString(&p)  // public point
      var scalar = try SSHWire.readString(&p)
      let size = type.hasSuffix("256") ? 32 : type.hasSuffix("384") ? 48 : 66
      while scalar.count > size && scalar.first == 0 { scalar.removeFirst() }
      while scalar.count < size { scalar.insert(0, at: 0) }
      let comment = String(decoding: try SSHWire.readString(&p), as: UTF8.self)
      return try SSHKey(kind: Kind(rawValue: type)!, privateBytes: scalar, comment: comment)
    case "ssh-rsa":
      let n = try SSHWire.readString(&p)
      let e = try SSHWire.readString(&p)
      let d = try SSHWire.readString(&p)
      let iqmp = try SSHWire.readString(&p)
      let prime1 = try SSHWire.readString(&p)
      let prime2 = try SSHWire.readString(&p)
      let comment = String(decoding: try SSHWire.readString(&p), as: UTF8.self)
      let pkcs1 = SSHRSA.pkcs1(n: n, e: e, d: d, p: prime1, q: prime2, qInverse: iqmp)
      return try SSHKey(kind: .rsa, privateBytes: pkcs1, comment: comment)
    default:
      throw ImportError.unsupportedType(type)
    }
  }

  /// Unencrypted OpenSSH private key text, for saving a generated key to a file.
  public var openSSHPrivateKey: String {
    let blob = (try? publicKeyBlob()) ?? []
    var priv = ByteWriter()
    let check = UInt32.random(in: 0...UInt32.max)
    priv.writeBE(check)
    priv.writeBE(check)
    SSHWire.string(&priv, Array(kind.rawValue.utf8))
    switch kind {
    case .ed25519:
      let pub = Array(blob.suffix(32))
      SSHWire.string(&priv, pub)
      SSHWire.string(&priv, privateBytes + pub)
    case .ecdsaP256, .ecdsaP384, .ecdsaP521:
      var br = ByteReader(blob)
      _ = try? SSHWire.readString(&br)
      let curve = (try? SSHWire.readString(&br)) ?? []
      let point = (try? SSHWire.readString(&br)) ?? []
      SSHWire.string(&priv, curve)
      SSHWire.string(&priv, point)
      SSHWire.mpint(&priv, privateBytes)
    case .rsa:
      return ""  // RSA keys are imported, never generated.
    }
    SSHWire.string(&priv, Array(comment.utf8))
    var pad: UInt8 = 1
    while priv.count % 8 != 0 {
      priv.write(pad)
      pad += 1
    }
    var w = ByteWriter()
    w.write(Array("openssh-key-v1".utf8) + [0])
    SSHWire.string(&w, Array("none".utf8))
    SSHWire.string(&w, Array("none".utf8))
    SSHWire.string(&w, [])
    w.writeBE(UInt32(1))
    SSHWire.string(&w, blob)
    SSHWire.string(&w, priv.bytes)
    let base64 = Data(w.bytes).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(base64)\n-----END OPENSSH PRIVATE KEY-----\n"
  }
}

/// SSH wire-format strings and mpints.
enum SSHWire {
  static func string(_ w: inout ByteWriter, _ bytes: [UInt8]) {
    w.writeBE(UInt32(bytes.count))
    w.write(bytes)
  }

  static func mpint(_ w: inout ByteWriter, _ bytes: [UInt8]) {
    var payload = Array(bytes.drop { $0 == 0 })
    if let first = payload.first, first & 0x80 != 0 { payload.insert(0, at: 0) }
    string(&w, payload)
  }

  static func readString(_ r: inout ByteReader) throws -> [UInt8] {
    let length = Int(try r.readBE(UInt32.self))
    return try r.readBytes(length)
  }
}

/// RSA through Security.framework, with the key held as PKCS#1 DER.
enum SSHRSA {
  static func secKey(_ pkcs1: [UInt8]) throws -> SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(Data(pkcs1) as CFData, attributes as CFDictionary, &error) else {
      throw SSHKey.ImportError.unrecognized
    }
    return key
  }

  static func publicNumbers(pkcs1: [UInt8]) throws -> (n: [UInt8], e: [UInt8]) {
    var r = ByteReader(pkcs1)
    guard try r.readByte() == 0x30 else { throw SSHKey.ImportError.unrecognized }
    _ = try DER.length(&r)
    _ = try DER.integer(&r)  // version
    return (try DER.integer(&r), try DER.integer(&r))
  }

  static func signSHA256(pkcs1: [UInt8], data: [UInt8]) throws -> [UInt8] {
    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        try secKey(pkcs1), .rsaSignatureMessagePKCS1v15SHA256, Data(data) as CFData, &error)
    else { throw WireError.authenticationFailed("RSA signing failed") }
    return [UInt8](signature as Data)
  }

  /// Builds PKCS#1 RSAPrivateKey, computing d mod (p-1) and d mod (q-1).
  static func pkcs1(n: [UInt8], e: [UInt8], d: [UInt8], p: [UInt8], q: [UInt8], qInverse: [UInt8]) -> [UInt8] {
    let one = BigUInt([1])
    let dp = BigUInt(d) % (BigUInt(p) - one)
    let dq = BigUInt(d) % (BigUInt(q) - one)
    var body: [UInt8] = []
    for value in [[0], n, e, d, p, q, dp.bytes, dq.bytes, qInverse] { body += DER.encodeInteger(value) }
    return [0x30] + DER.encodeLength(body.count) + body
  }
}

enum DER {
  static func length(_ r: inout ByteReader) throws -> Int {
    let first = try r.readByte()
    if first & 0x80 == 0 { return Int(first) }
    var value = 0
    for _ in 0..<Int(first & 0x7F) { value = value << 8 | Int(try r.readByte()) }
    return value
  }

  static func integer(_ r: inout ByteReader) throws -> [UInt8] {
    guard try r.readByte() == 0x02 else { throw SSHKey.ImportError.unrecognized }
    let bytes = try r.readBytes(try length(&r))
    return Array(bytes.drop { $0 == 0 })
  }

  static func encodeLength(_ n: Int) -> [UInt8] {
    if n < 0x80 { return [UInt8(n)] }
    var bytes: [UInt8] = []
    var v = n
    while v > 0 {
      bytes.insert(UInt8(v & 0xFF), at: 0)
      v >>= 8
    }
    return [0x80 | UInt8(bytes.count)] + bytes
  }

  static func encodeInteger(_ value: [UInt8]) -> [UInt8] {
    var v = Array(value.drop { $0 == 0 })
    if v.isEmpty { v = [0] }
    if v[0] & 0x80 != 0 { v.insert(0, at: 0) }
    return [0x02] + encodeLength(v.count) + v
  }
}

/// Just enough unsigned big-integer arithmetic for RSA key conversion.
struct BigUInt {
  /// Big-endian bytes without leading zeros.
  var bytes: [UInt8]

  init(_ bytes: [UInt8]) { self.bytes = Array(bytes.drop { $0 == 0 }) }

  static func - (a: BigUInt, b: BigUInt) -> BigUInt {
    var result = a.bytes
    var borrow = 0
    var j = b.bytes.count - 1
    for i in stride(from: result.count - 1, through: 0, by: -1) {
      var value = Int(result[i]) - borrow - (j >= 0 ? Int(b.bytes[j]) : 0)
      borrow = 0
      if value < 0 {
        value += 256
        borrow = 1
      }
      result[i] = UInt8(value)
      j -= 1
    }
    return BigUInt(result)
  }

  static func >= (a: BigUInt, b: BigUInt) -> Bool {
    if a.bytes.count != b.bytes.count { return a.bytes.count > b.bytes.count }
    for (x, y) in zip(a.bytes, b.bytes) where x != y { return x > y }
    return true
  }

  /// Bitwise long division remainder.
  static func % (a: BigUInt, m: BigUInt) -> BigUInt {
    var remainder = BigUInt([])
    for byte in a.bytes {
      for bit in stride(from: 7, through: 0, by: -1) {
        // remainder = remainder * 2 + bit
        let count = remainder.bytes.count
        var shifted = [UInt8](repeating: 0, count: count + 1)
        var carry: UInt8 = (byte >> UInt8(bit)) & 1
        for i in stride(from: count - 1, through: 0, by: -1) {
          let b = remainder.bytes[i]
          shifted[i + 1] = (b << 1) | carry
          carry = b >> 7
        }
        shifted[0] = carry
        remainder = BigUInt(shifted)
        if remainder >= m { remainder = remainder - m }
      }
    }
    return remainder
  }
}
