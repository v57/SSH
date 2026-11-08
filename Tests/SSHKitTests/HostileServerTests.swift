#if canImport(Darwin)
import CryptoKit
import Darwin
import Foundation
import Testing

@testable import SSHKit

/// A server that speaks just enough SSH to finish a key exchange (ecdh-sha2-nistp256, an ECDSA host key,
/// chacha20-poly1305@openssh.com) and then sends one hostile packet before the host key is checked: the packets of
/// libssh2's pre-authentication bugs (CVE-2026-55200, CVE-2026-55199). The control proves the fake server's crypto is
/// right: libssh2 accepts its packets and gets as far as logging in.
@Suite(.serialized, .timeLimit(.minutes(1)))
struct HostileServerTests {
  @Test func controlServerGetsAsFarAsTheLogin() async throws {
    let server = try HostileServer { session in
      try session.sendEncrypted(HostileServer.extInfo(count: 1, entries: [("server-sig-algs", "ecdsa-sha2-nistp256")]))
      try session.sendEncrypted([6] + HostileServer.string("ssh-userauth"))
    }
    let asked = Flag()
    let error = await connectError(port: server.port) { asked.set() }
    #expect(asked.isSet, "the handshake should finish and the host key be asked about: \(String(describing: error))")
    if case .authenticationFailed = error as? SSHTunnelError {} else {
      Issue.record("expected the login to fail after a good handshake, got \(String(describing: error))")
    }
  }

  /// CVE-2026-55200: a chacha20-poly1305 packet length that overflows packet_length + auth_len to 4. Unpatched, libssh2
  /// allocates 4 bytes and decrypts ~4 GB into them (a heap write, here a crash of the test process).
  @Test func packetLengthPastTheLimitIsRefused() async throws {
    let server = try HostileServer { session in
      try session.sendLength(0xFFFF_FFF0, followedBy: Data(count: 60))
    }
    let started = Date()
    let error = await connectError(port: server.port)
    guard case .handshakeFailed = error as? SSHTunnelError else {
      Issue.record("expected the handshake to fail, got \(String(describing: error))")
      return
    }
    #expect(Date().timeIntervalSince(started) < 5)
  }

  /// CVE-2026-55199: EXT_INFO claiming 4 billion extensions in a short body. Unpatched, libssh2 spins through every
  /// one of them before the host key is checked.
  @Test func extensionInfoWithEndlessEntriesIsRefusedAtOnce() async throws {
    let server = try HostileServer { session in
      try session.sendEncrypted(HostileServer.extInfo(count: 0xFFFF_FFFF, entries: [("a", "b")]))
      try session.sendEncrypted([6] + HostileServer.string("ssh-userauth"))
    }
    let started = Date()
    let error = await connectError(port: server.port, timeout: 30)
    guard case .handshakeFailed = error as? SSHTunnelError else {
      Issue.record("expected the handshake to fail, got \(String(describing: error))")
      return
    }
    #expect(Date().timeIntervalSince(started) < 1, "took \(Date().timeIntervalSince(started)) s")
  }

  private func connectError(port: Int, timeout: TimeInterval = 10, asked: @escaping @Sendable () -> Void = {}) async
    -> Error?
  {
    let trust = SSHHostTrust.ask { _ in
      asked()
      return true
    }
    let server = SSHServer(host: "127.0.0.1", port: port, user: "nobody", password: "not-a-password", trust: trust)
    do {
      let connection = try await SSHConnection.connect(server: server, timeout: timeout)
      connection.close()
      return nil
    } catch {
      return error
    }
  }
}

final class Flag: @unchecked Sendable {
  private let lock = NSLock()
  private var value = false
  func set() { lock.withLock { value = true } }
  var isSet: Bool { lock.withLock { value } }
}

/// One connection on a loopback port: banner, KEXINIT, ECDH reply, NEWKEYS, then `script` with the server-to-client
/// keys in place.
final class HostileServer: @unchecked Sendable {
  let port: Int
  private let listener: Int32

  init(script: @escaping @Sendable (HostileServer.Session) throws -> Void) throws {
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    self.listener = listener
    var address = sockaddr_in()
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = 0
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
        bind(listener, pointer, length) == 0 && listen(listener, 1) == 0
          && getsockname(listener, pointer, &length) == 0
      }
    }
    guard bound else { throw POSIXError(.EADDRINUSE) }
    port = Int(UInt16(bigEndian: address.sin_port))
    Thread.detachNewThread {
      let client = accept(listener, nil, nil)
      guard client >= 0 else { return }
      defer { Darwin.close(client) }
      let session = Session(socket: client)
      do {
        try session.keyExchange()
        try script(session)
        // Keep the line open a moment so the client reads everything before it sees the end.
        Thread.sleep(forTimeInterval: 0.5)
      } catch {}
    }
  }

  deinit { Darwin.close(listener) }

  // MARK: Wire

  static func u32(_ value: UInt32) -> [UInt8] { withUnsafeBytes(of: value.bigEndian, Array.init) }
  static func string(_ bytes: [UInt8]) -> [UInt8] { u32(UInt32(bytes.count)) + bytes }
  static func string(_ text: String) -> [UInt8] { string(Array(text.utf8)) }
  static func mpint(_ bytes: [UInt8]) -> [UInt8] {
    var bytes = Array(bytes.drop { $0 == 0 })
    if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
    return string(bytes)
  }

  /// SSH_MSG_EXT_INFO claiming `count` entries.
  static func extInfo(count: UInt32, entries: [(String, String)]) -> [UInt8] {
    [7] + u32(count) + entries.flatMap { string($0.0) + string($0.1) }
  }

  final class Session {
    let socket: Int32
    private var sequence: UInt32 = 0
    private var mainKey: [UInt8] = []
    private var headerKey: [UInt8] = []

    init(socket: Int32) { self.socket = socket }

    func write(_ bytes: [UInt8]) throws {
      var offset = 0
      while offset < bytes.count {
        let sent = bytes[offset...].withUnsafeBytes { Darwin.send(socket, $0.baseAddress, $0.count, 0) }
        guard sent > 0 else { throw POSIXError(.EPIPE) }
        offset += sent
      }
    }

    func read(_ count: Int) throws -> [UInt8] {
      var bytes = [UInt8](repeating: 0, count: count)
      var offset = 0
      while offset < count {
        let got = bytes[offset...].withUnsafeMutableBytes { recv(socket, $0.baseAddress, $0.count, 0) }
        guard got > 0 else { throw POSIXError(.ECONNRESET) }
        offset += got
      }
      return bytes
    }

    func readLine() throws -> String {
      var line: [UInt8] = []
      while true {
        let byte = try read(1)[0]
        if byte == 0x0A { break }
        if byte != 0x0D { line.append(byte) }
      }
      return String(decoding: line, as: UTF8.self)
    }

    func readPacket() throws -> [UInt8] {
      let length = try read(4).reduce(0) { $0 << 8 | Int($1) }
      let packet = try read(length)
      return Array(packet[1..<(length - Int(packet[0]))])
    }

    func sendPlain(_ payload: [UInt8]) throws {
      var padding = 8 - (5 + payload.count) % 8
      if padding < 4 { padding += 8 }
      try write(u32(UInt32(1 + payload.count + padding)) + [UInt8(padding)] + payload + [UInt8](repeating: 0, count: padding))
      sequence &+= 1
    }

    func keyExchange() throws {
      let serverVersion = "SSH-2.0-HostileServer_1.0"
      try write(Array((serverVersion + "\r\n").utf8))
      var clientVersion = ""
      repeat { clientVersion = try readLine() } while !clientVersion.hasPrefix("SSH-")

      let names = [
        "ecdh-sha2-nistp256", "ecdsa-sha2-nistp256", "chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com",
        "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "",
      ]
      let serverInit: [UInt8] = [20] + [UInt8](repeating: 7, count: 16) + names.flatMap { string($0) } + [0] + u32(0)
      try sendPlain(serverInit)
      var clientInit: [UInt8] = []
      repeat { clientInit = try readPacket() } while clientInit.first != 20
      var ecdhInit: [UInt8] = []
      repeat { ecdhInit = try readPacket() } while ecdhInit.first != 30
      let clientPoint = Array(ecdhInit[5...])

      let hostKey = P256.Signing.PrivateKey()
      let ephemeral = P256.KeyAgreement.PrivateKey()
      let clientKey = try P256.KeyAgreement.PublicKey(x963Representation: clientPoint)
      let shared = try ephemeral.sharedSecretFromKeyAgreement(with: clientKey).withUnsafeBytes { Array($0) }
      let serverPoint = Array(ephemeral.publicKey.x963Representation)
      let hostBlob = string("ecdsa-sha2-nistp256") + string("nistp256") + string(Array(hostKey.publicKey.x963Representation))
      let k = mpint(shared)
      let exchange =
        string(clientVersion) + string(serverVersion) + string(clientInit) + string(serverInit) + string(hostBlob)
        + string(clientPoint) + string(serverPoint) + k
      let h = Array(SHA256.hash(data: exchange))
      let signature = try hostKey.signature(for: h).rawRepresentation
      let signatureBlob =
        string("ecdsa-sha2-nistp256") + string(mpint(Array(signature[..<32])) + mpint(Array(signature[32...])))
      try sendPlain([31] + string(hostBlob) + string(serverPoint) + string(signatureBlob))
      try sendPlain([21])
      var newKeys: [UInt8] = []
      repeat { newKeys = try readPacket() } while newKeys.first != 21

      // Server to client ("D"), 64 bytes: K1 = HASH(K || H || "D" || session id), K2 = HASH(K || H || K1).
      let k1 = Array(SHA256.hash(data: k + h + [UInt8(ascii: "D")] + h))
      let k2 = Array(SHA256.hash(data: k + h + k1))
      mainKey = k1
      headerKey = k2
    }

    /// A chacha20-poly1305@openssh.com packet.
    func sendEncrypted(_ payload: [UInt8]) throws {
      var padding = 8 - (1 + payload.count) % 8
      if padding < 4 { padding += 8 }
      let body = [UInt8(padding)] + payload + [UInt8](repeating: 0, count: padding)
      let nonce = withUnsafeBytes(of: UInt64(sequence).bigEndian, Array.init)
      let length = ChaCha20.xor(u32(UInt32(body.count)), key: headerKey, nonce: nonce, counter: 0)
      let encrypted = ChaCha20.xor(body, key: mainKey, nonce: nonce, counter: 1)
      let polyKey = Array(ChaCha20.block(key: mainKey, nonce: nonce, counter: 0)[..<32])
      let tag = Poly1305.tag(length + encrypted, key: polyKey)
      try write(length + encrypted + tag)
      sequence &+= 1
    }

    /// Only an encrypted length field (anything may follow it).
    func sendLength(_ value: UInt32, followedBy rest: Data) throws {
      let nonce = withUnsafeBytes(of: UInt64(sequence).bigEndian, Array.init)
      try write(ChaCha20.xor(u32(value), key: headerKey, nonce: nonce, counter: 0) + Array(rest))
    }

    private func u32(_ value: UInt32) -> [UInt8] { HostileServer.u32(value) }
    private func string(_ bytes: [UInt8]) -> [UInt8] { HostileServer.string(bytes) }
    private func string(_ text: String) -> [UInt8] { HostileServer.string(text) }
    private func mpint(_ bytes: [UInt8]) -> [UInt8] { HostileServer.mpint(bytes) }
  }
}

/// ChaCha20 as libssh2's chacha.c has it (D. J. Bernstein's: a 64-bit counter and a 64-bit nonce).
enum ChaCha20 {
  static func block(key: [UInt8], nonce: [UInt8], counter: UInt64) -> [UInt8] {
    func word(_ bytes: [UInt8], _ at: Int) -> UInt32 {
      UInt32(bytes[at]) | UInt32(bytes[at + 1]) << 8 | UInt32(bytes[at + 2]) << 16 | UInt32(bytes[at + 3]) << 24
    }
    var state: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
    state += (0..<8).map { word(key, $0 * 4) }
    state += [UInt32(truncatingIfNeeded: counter), UInt32(truncatingIfNeeded: counter >> 32), word(nonce, 0), word(nonce, 4)]
    var x = state
    func quarter(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
      x[a] &+= x[b]; x[d] ^= x[a]; x[d] = x[d] << 16 | x[d] >> 16
      x[c] &+= x[d]; x[b] ^= x[c]; x[b] = x[b] << 12 | x[b] >> 20
      x[a] &+= x[b]; x[d] ^= x[a]; x[d] = x[d] << 8 | x[d] >> 24
      x[c] &+= x[d]; x[b] ^= x[c]; x[b] = x[b] << 7 | x[b] >> 25
    }
    for _ in 0..<10 {
      quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
      quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
    }
    return (0..<16).flatMap { i in withUnsafeBytes(of: (x[i] &+ state[i]).littleEndian, Array.init) }
  }

  static func xor(_ data: [UInt8], key: [UInt8], nonce: [UInt8], counter: UInt64) -> [UInt8] {
    var out = data
    for start in stride(from: 0, to: data.count, by: 64) {
      let stream = block(key: key, nonce: nonce, counter: counter + UInt64(start / 64))
      for i in start..<min(start + 64, data.count) { out[i] ^= stream[i - start] }
    }
    return out
  }
}

/// Poly1305 (poly1305-donna's 26-bit limbs).
enum Poly1305 {
  static func tag(_ message: [UInt8], key: [UInt8]) -> [UInt8] {
    func le(_ bytes: [UInt8], _ at: Int) -> UInt64 {
      UInt64(bytes[at]) | UInt64(bytes[at + 1]) << 8 | UInt64(bytes[at + 2]) << 16 | UInt64(bytes[at + 3]) << 24
    }
    let mask: UInt64 = 0x3ff_ffff
    let r0 = le(key, 0) & 0x3ff_ffff, r1 = (le(key, 3) >> 2) & 0x3ff_ff03, r2 = (le(key, 6) >> 4) & 0x3ff_c0ff
    let r3 = (le(key, 9) >> 6) & 0x3f0_3fff, r4 = (le(key, 12) >> 8) & 0x00f_ffff
    let s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5
    var h0: UInt64 = 0, h1: UInt64 = 0, h2: UInt64 = 0, h3: UInt64 = 0, h4: UInt64 = 0
    var offset = 0
    while offset < message.count {
      var block = Array(message[offset..<min(offset + 16, message.count)])
      var hibit: UInt64 = 1 << 24
      if block.count < 16 {
        block.append(1)
        block += [UInt8](repeating: 0, count: 16 - block.count)
        hibit = 0
      }
      offset += 16
      h0 += le(block, 0) & mask
      h1 += (le(block, 3) >> 2) & mask
      h2 += (le(block, 6) >> 4) & mask
      h3 += (le(block, 9) >> 6) & mask
      h4 += (le(block, 12) >> 8) | hibit
      let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0
      var c = d0 >> 26; h0 = d0 & mask
      d1 += c; c = d1 >> 26; h1 = d1 & mask
      d2 += c; c = d2 >> 26; h2 = d2 & mask
      d3 += c; c = d3 >> 26; h3 = d3 & mask
      d4 += c; c = d4 >> 26; h4 = d4 & mask
      h0 += c * 5; c = h0 >> 26; h0 &= mask
      h1 += c
    }
    var c = h1 >> 26; h1 &= mask
    h2 += c; c = h2 >> 26; h2 &= mask
    h3 += c; c = h3 >> 26; h3 &= mask
    h4 += c; c = h4 >> 26; h4 &= mask
    h0 += c * 5; c = h0 >> 26; h0 &= mask
    h1 += c
    var g0 = h0 &+ 5; c = g0 >> 26; g0 &= mask
    var g1 = h1 &+ c; c = g1 >> 26; g1 &= mask
    var g2 = h2 &+ c; c = g2 >> 26; g2 &= mask
    var g3 = h3 &+ c; c = g3 >> 26; g3 &= mask
    let g4 = h4 &+ c &- (1 << 26)
    let select = (g4 >> 63) &- 1  // all ones when h >= p: take g
    h0 = (h0 & ~select) | (g0 & select)
    h1 = (h1 & ~select) | (g1 & select)
    h2 = (h2 & ~select) | (g2 & select)
    h3 = (h3 & ~select) | (g3 & select)
    h4 = (h4 & ~select) | (g4 & select)
    let w0 = (h0 | h1 << 26) & 0xffff_ffff
    let w1 = (h1 >> 6 | h2 << 20) & 0xffff_ffff
    let w2 = (h2 >> 12 | h3 << 14) & 0xffff_ffff
    let w3 = (h3 >> 18 | h4 << 8) & 0xffff_ffff
    var f = w0 + le(key, 16)
    var out = withUnsafeBytes(of: UInt32(truncatingIfNeeded: f).littleEndian, Array.init)
    f = w1 + le(key, 20) + (f >> 32)
    out += withUnsafeBytes(of: UInt32(truncatingIfNeeded: f).littleEndian, Array.init)
    f = w2 + le(key, 24) + (f >> 32)
    out += withUnsafeBytes(of: UInt32(truncatingIfNeeded: f).littleEndian, Array.init)
    f = w3 + le(key, 28) + (f >> 32)
    out += withUnsafeBytes(of: UInt32(truncatingIfNeeded: f).littleEndian, Array.init)
    return out
  }
}

/// The two constructions the fake server rests on, against their published vectors.
@Suite struct HostileServerCryptoTests {
  @Test func poly1305MatchesRFC8439() {
    let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    let tag = Poly1305.tag(Array("Cryptographic Forum Research Group".utf8), key: key)
    #expect(tag == hex("a8061dc1305136c6c22b8baf0c0127a9"))
  }

  @Test func chacha20MatchesTheOriginalVectors() {
    // draft-agl-tls-chacha20poly1305-04, test vector 1: all-zero key and nonce.
    let block = ChaCha20.block(key: [UInt8](repeating: 0, count: 32), nonce: [UInt8](repeating: 0, count: 8), counter: 0)
    #expect(Array(block[..<32]) == hex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"))
  }

  private func hex(_ text: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = text.startIndex
    while index < text.endIndex {
      let next = text.index(index, offsetBy: 2)
      bytes.append(UInt8(text[index..<next], radix: 16)!)
      index = next
    }
    return bytes
  }
}
#endif
