import CryptoKit
import Foundation
#if canImport(CommonCrypto)
  import CommonCrypto
#else
  import _CryptoExtras
#endif

/// Opens the private part of passphrase-protected keys: OpenSSH's format (bcrypt_pbkdf and AES) and the older PEM one
/// (`DEK-Info`, MD5 and AES-CBC). What ssh-keygen can write that isn't here (chacha20-poly1305, encrypted PKCS#8,
/// 3DES) is refused by name, with the command that converts it.
enum SSHKeyDecryption {
  private enum Mode { case ctr, cbc, gcm }

  private static let openSSHCiphers: [String: (mode: Mode, keySize: Int, ivSize: Int)] = [
    "aes128-ctr": (.ctr, 16, 16), "aes192-ctr": (.ctr, 24, 16), "aes256-ctr": (.ctr, 32, 16),
    "aes128-cbc": (.cbc, 16, 16), "aes192-cbc": (.cbc, 24, 16), "aes256-cbc": (.cbc, 32, 16),
    "aes128-gcm@openssh.com": (.gcm, 16, 12), "aes256-gcm@openssh.com": (.gcm, 32, 12),
  ]

  /// More rounds than any key needs would only freeze whoever opens a file made to do that.
  private static let maximumRounds = 1 << 16

  /// The private section of an OpenSSH key, opened. `encrypted` is what follows its length, with GCM's tag.
  static func openSSH(
    cipher: String, kdf: String, kdfOptions: [UInt8], encrypted: [UInt8], tag: [UInt8], passphrase: String
  ) throws -> [UInt8] {
    guard let spec = openSSHCiphers[cipher] else { throw SSHKey.ImportError.unsupportedEncryption(cipher) }
    guard kdf == "bcrypt" else { throw SSHKey.ImportError.unsupportedEncryption(kdf) }
    var options = SSHWire.Reader(kdfOptions)
    let salt = try SSHWire.readString(&options)
    let rounds = Int(try options.readBE(UInt32.self))
    guard rounds >= 1, rounds <= maximumRounds, !salt.isEmpty else { throw SSHKey.ImportError.unrecognized }
    var password = Array(passphrase.utf8)
    defer { SSHSecretBytes.wipe(&password) }
    var derived = SSHBcryptPBKDF.derive(password: password, salt: salt, count: spec.keySize + spec.ivSize, rounds: rounds)
    defer { SSHSecretBytes.wipe(&derived) }
    var key = Array(derived[..<spec.keySize])
    defer { SSHSecretBytes.wipe(&key) }
    let iv = Array(derived[spec.keySize...])
    switch spec.mode {
    case .ctr: return try aesCTR(key: key, iv: iv, encrypted)
    case .cbc:
      guard encrypted.count % 16 == 0 else { throw SSHKey.ImportError.unrecognized }
      return try aesCBC(key: key, iv: iv, encrypted)
    case .gcm:
      guard tag.count == 16 else { throw SSHKey.ImportError.unrecognized }
      do {
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: encrypted, tag: tag)
        return Array(try AES.GCM.open(box, using: SymmetricKey(data: key)))
      } catch {
        throw SSHKey.ImportError.wrongPassphrase
      }
    }
  }

  /// How long a tag follows the private section of a key with this cipher.
  static func tagSize(cipher: String) -> Int {
    openSSHCiphers[cipher]?.mode == .gcm ? 16 : 0
  }

  /// The DER inside a PEM block with `DEK-Info: <cipher>,<hex iv>`: an AES-CBC key from MD5 of the passphrase and the
  /// IV's first 8 bytes, as OpenSSL's `EVP_BytesToKey` makes it.
  static func pem(dekInfo: String, encrypted: [UInt8], passphrase: String) throws -> [UInt8] {
    let parts = dekInfo.split(separator: ",", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
    guard parts.count == 2 else { throw SSHKey.ImportError.unrecognized }
    guard let keySize = ["AES-128-CBC": 16, "AES-192-CBC": 24, "AES-256-CBC": 32][parts[0].uppercased()] else {
      throw SSHKey.ImportError.unsupportedEncryption(parts[0])
    }
    guard let iv = bytes(hex: parts[1]), iv.count == 16, !encrypted.isEmpty, encrypted.count % 16 == 0 else {
      throw SSHKey.ImportError.unrecognized
    }
    var password = Array(passphrase.utf8)
    defer { SSHSecretBytes.wipe(&password) }
    var key: [UInt8] = []
    defer { SSHSecretBytes.wipe(&key) }
    var block: [UInt8] = []
    while key.count < keySize {
      var input = block + password + iv.prefix(8)
      defer { SSHSecretBytes.wipe(&input) }
      block = Array(Insecure.MD5.hash(data: input))
      key += block
    }
    var opened = try aesCBC(key: Array(key.prefix(keySize)), iv: iv, encrypted)
    // PKCS#7 padding. A wrong passphrase rarely leaves a valid one.
    guard let padding = opened.last, padding >= 1, padding <= 16, opened.suffix(Int(padding)).allSatisfy({ $0 == padding })
    else {
      SSHSecretBytes.wipe(&opened)
      throw SSHKey.ImportError.wrongPassphrase
    }
    return Array(opened.dropLast(Int(padding)))
  }

  private static func bytes(hex: String) -> [UInt8]? {
    guard hex.count % 2 == 0 else { return nil }
    var result: [UInt8] = []
    var rest = Substring(hex)
    while !rest.isEmpty {
      guard let byte = UInt8(rest.prefix(2), radix: 16) else { return nil }
      result.append(byte)
      rest = rest.dropFirst(2)
    }
    return result
  }

  #if canImport(CommonCrypto)
    private static func aesCTR(key: [UInt8], iv: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
      try commonCrypto(CCMode(kCCModeCTR), options: CCModeOptions(kCCModeOptionCTR_BE), key: key, iv: iv, data)
    }

    private static func aesCBC(key: [UInt8], iv: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
      try commonCrypto(CCMode(kCCModeCBC), options: 0, key: key, iv: iv, data)
    }

    private static func commonCrypto(
      _ mode: CCMode, options: CCModeOptions, key: [UInt8], iv: [UInt8], _ data: [UInt8]
    ) throws -> [UInt8] {
      var cryptor: CCCryptorRef?
      let created = CCCryptorCreateWithMode(
        CCOperation(kCCDecrypt), mode, CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), iv, key, key.count, nil, 0, 0,
        options, &cryptor)
      guard created == kCCSuccess, let cryptor else { throw SSHKey.ImportError.unrecognized }
      defer { CCCryptorRelease(cryptor) }
      var output = [UInt8](repeating: 0, count: data.count)
      var moved = 0
      guard CCCryptorUpdate(cryptor, data, data.count, &output, output.count, &moved) == kCCSuccess, moved == data.count
      else {
        throw SSHKey.ImportError.unrecognized
      }
      return output
    }
  #else
    private static func aesCTR(key: [UInt8], iv: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
      Array(try AES._CTR.decrypt(data, using: SymmetricKey(data: key), nonce: AES._CTR.Nonce(nonceBytes: iv)))
    }

    private static func aesCBC(key: [UInt8], iv: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
      Array(try AES._CBC.decrypt(data, using: SymmetricKey(data: key), iv: AES._CBC.IV(ivBytes: iv), noPadding: true))
    }
  #endif
}

/// bcrypt_pbkdf, the key derivation of OpenSSH's key format, from `Sources/CLibssh2/src/bcrypt_pbkdf.c` (Ted Unangst's
/// OpenBSD implementation). libssh2 has it, but only for its own keys and not as an API.
enum SSHBcryptPBKDF {
  private static let hashSize = 32

  static func derive(password: [UInt8], salt: [UInt8], count: Int, rounds: Int) -> [UInt8] {
    let stride = (count + hashSize - 1) / hashSize
    let amount = (count + stride - 1) / stride
    var hashedPassword = Array(SHA512.hash(data: password))
    defer { SSHSecretBytes.wipe(&hashedPassword) }
    var key = [UInt8](repeating: 0, count: count)
    var remaining = count
    var block: UInt32 = 1
    while remaining > 0 {
      let counter = withUnsafeBytes(of: block.bigEndian) { Array($0) }
      var salted = Array(SHA512.hash(data: salt + counter))
      var hash = bcryptHash(hashedPassword, salted)
      var output = hash
      for _ in 1..<max(rounds, 1) {
        salted = Array(SHA512.hash(data: hash))
        hash = bcryptHash(hashedPassword, salted)
        for j in 0..<hashSize { output[j] ^= hash[j] }
      }
      // Unlike PBKDF2, the output is spread over the key, so no part of it comes cheaper.
      var written = 0
      while written < min(amount, remaining) {
        let destination = written * stride + Int(block - 1)
        if destination >= count { break }
        key[destination] = output[written]
        written += 1
      }
      remaining -= written
      block += 1
      SSHSecretBytes.wipe(&output)
      SSHSecretBytes.wipe(&hash)
      SSHSecretBytes.wipe(&salted)
    }
    return key
  }

  private static func bcryptHash(_ password: [UInt8], _ salt: [UInt8]) -> [UInt8] {
    let state = Blowfish()
    defer { state.wipe() }
    state.expand(data: salt, key: password)
    for _ in 0..<64 {
      state.expand0(key: salt)
      state.expand0(key: password)
    }
    var words: [UInt32] = []
    var position = 0
    let text = Array("OxychromaticBlowfishSwatDynamite".utf8)
    for _ in 0..<(hashSize / 4) { words.append(Blowfish.word(text, &position)) }
    for _ in 0..<64 {
      for block in stride(from: 0, to: words.count, by: 2) {
        (words[block], words[block + 1]) = state.encipher(words[block], words[block + 1])
      }
    }
    var result: [UInt8] = []
    result.reserveCapacity(hashSize)
    for word in words { withUnsafeBytes(of: word.littleEndian) { result.append(contentsOf: $0) } }
    return result
  }

  /// The eksblowfish state, in memory of its own: this runs thousands of times per key, also in debug builds.
  private final class Blowfish {
    private let s: UnsafeMutablePointer<UInt32>
    private let p: UnsafeMutablePointer<UInt32>

    init() {
      s = .allocate(capacity: 1024)
      p = .allocate(capacity: 18)
      SSHBlowfishTables.s.withUnsafeBufferPointer { s.initialize(from: $0.baseAddress!, count: 1024) }
      SSHBlowfishTables.p.withUnsafeBufferPointer { p.initialize(from: $0.baseAddress!, count: 18) }
    }

    deinit {
      s.deallocate()
      p.deallocate()
    }

    func wipe() {
      SSHSecretBytes.wipe(UnsafeMutableRawBufferPointer(start: s, count: 1024 * 4))
      SSHSecretBytes.wipe(UnsafeMutableRawBufferPointer(start: p, count: 18 * 4))
    }

    @inline(__always) private func f(_ x: UInt32) -> UInt32 {
      let a = s[Int(x >> 24)]
      let b = s[0x100 + Int((x >> 16) & 0xFF)]
      let c = s[0x200 + Int((x >> 8) & 0xFF)]
      let d = s[0x300 + Int(x & 0xFF)]
      return ((a &+ b) ^ c) &+ d
    }

    func encipher(_ left: UInt32, _ right: UInt32) -> (UInt32, UInt32) {
      var l = left ^ p[0]
      var r = right
      var round = 1
      while round <= 16 {
        r ^= f(l) ^ p[round]
        l ^= f(r) ^ p[round + 1]
        round += 2
      }
      return (r ^ p[17], l)
    }

    /// The next 4 bytes of `data` as a big-endian word, going round when it ends.
    static func word(_ data: [UInt8], _ position: inout Int) -> UInt32 {
      var value: UInt32 = 0
      for _ in 0..<4 {
        if position >= data.count { position = 0 }
        value = value << 8 | UInt32(data[position])
        position += 1
      }
      return value
    }

    private func mixKey(_ key: [UInt8]) {
      var position = 0
      for i in 0..<18 { p[i] ^= Self.word(key, &position) }
    }

    func expand(data: [UInt8], key: [UInt8]) {
      mixKey(key)
      var position = 0
      var left: UInt32 = 0
      var right: UInt32 = 0
      func next() {
        left ^= Self.word(data, &position)
        right ^= Self.word(data, &position)
        (left, right) = encipher(left, right)
      }
      for i in stride(from: 0, to: 18, by: 2) {
        next()
        p[i] = left
        p[i + 1] = right
      }
      for k in stride(from: 0, to: 1024, by: 2) {
        next()
        s[k] = left
        s[k + 1] = right
      }
    }

    func expand0(key: [UInt8]) {
      mixKey(key)
      var left: UInt32 = 0
      var right: UInt32 = 0
      for i in stride(from: 0, to: 18, by: 2) {
        (left, right) = encipher(left, right)
        p[i] = left
        p[i + 1] = right
      }
      for k in stride(from: 0, to: 1024, by: 2) {
        (left, right) = encipher(left, right)
        s[k] = left
        s[k + 1] = right
      }
    }
  }
}
