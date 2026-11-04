import CLibssh2
import Foundation
import Testing

@testable import SSHKit

/// What the libssh2 these tests link (the prebuilt one the apps ship, on Apple platforms) offers a server.
struct AlgorithmTests {
  private func withSession<T>(_ body: (OpaquePointer) -> T) throws -> T {
    _ = SSHLogin.initialized
    let session = try #require(libssh2_session_init_ex(nil, nil, nil, nil))
    defer { libssh2_session_free(session) }
    return body(session)
  }

  @Test func listsWhatThisBuildSupports() throws {
    try withSession { session in
      for method in SSHAlgorithms.methods {
        let names = SSHAlgorithms.supported(session, method: method)
        print("method \(method): \(names.joined(separator: ","))")
        #expect(!names.isEmpty)
        // Each method still has something to offer.
        #expect(names.contains { SSHAlgorithms.isAllowed($0, method: method) })
      }
    }
  }

  @Test(arguments: ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"])
  func sha1KeyExchangeIsOut(name: String) {
    #expect(!SSHAlgorithms.isAllowed(name, method: LIBSSH2_METHOD_KEX))
  }

  @Test(arguments: ["aes128-cbc", "aes256-cbc", "3des-cbc", "rijndael-cbc@lysator.liu.se", "arcfour", "blowfish-cbc", "none"])
  func oldCiphersAreOut(name: String) {
    #expect(!SSHAlgorithms.isAllowed(name, method: LIBSSH2_METHOD_CRYPT_CS))
  }

  @Test(arguments: ["hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "none"])
  func oldMACsAreOut(name: String) {
    #expect(!SSHAlgorithms.isAllowed(name, method: LIBSSH2_METHOD_MAC_CS))
  }

  #if canImport(Darwin)
    /// The first thing a client sends after its banner is its KEXINIT, in the clear, with all its lists: this listens
    /// on a loopback port for it, and compares with what must and mustn't be there.
    @Test func theClientOffersStrictKeyExchangeAndNoneOfTheRetiredAlgorithms() async throws {
      let listener = try KexInitListener()
      let client = Task.detached {
        let login = SSHLogin(
          server: SSHServer(host: "127.0.0.1", port: listener.port, user: "nobody", trust: .refuseUnknown), jump: nil)
        defer { login.teardown() }
        try? login.connect(timeout: 3)
      }
      let lists = try #require(await listener.nameLists())
      await client.value
      print("offered: \(lists)")
      let kex = lists[0]
      #expect(kex.contains("kex-strict-c-v00@openssh.com"))
      #expect(kex.contains("ext-info-c"))
      #expect(!kex.contains { $0.contains("sha1") })
      #expect(kex.contains { !$0.hasPrefix("kex-strict") && $0 != "ext-info-c" })
      #expect(!lists[1].contains { $0.hasPrefix("ssh-rsa") || $0.hasPrefix("ssh-dss") })
      for list in lists[2...3] { #expect(!list.isEmpty && !list.contains { $0.contains("cbc") || $0.contains("3des") }) }
      for list in lists[4...5] {
        #expect(!list.isEmpty && !list.contains { $0.contains("md5") || $0.contains("ripemd") || $0.hasPrefix("hmac-sha1") })
      }
    }
  #endif

  @Test(.enabled(if: TestServer.isUp, "needs an sshd on SSH_TEST_PORT"))
  func stillLogsInToAModernServer() async throws {
    let command = SSHCommand(server: try TestServer.server, command: "true")
    #expect(try await command.run { _ in } == 0)
  }
}

#if canImport(Darwin)
  private final class KexInitListener: @unchecked Sendable {
    let port: Int
    private let socket: Int32

    init() throws {
      let listening = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      var address = sockaddr_in()
      address.sin_family = sa_family_t(AF_INET)
      address.sin_addr.s_addr = inet_addr("127.0.0.1")
      address.sin_port = 0
      let size = socklen_t(MemoryLayout<sockaddr_in>.size)
      let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listening, $0, size) }
      }
      guard bound == 0, Darwin.listen(listening, 1) == 0 else { throw POSIXError(.EADDRINUSE) }
      var named = sockaddr_in()
      var length = size
      _ = withUnsafeMutablePointer(to: &named) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listening, $0, &length) }
      }
      socket = listening
      port = Int(UInt16(bigEndian: named.sin_port))
    }

    deinit { close(socket) }

    func nameLists() async -> [[String]]? {
      await withCheckedContinuation { continuation in
        Thread.detachNewThread { continuation.resume(returning: self.readLists()) }
      }
    }

    private func readLists() -> [[String]]? {
      let client = accept(socket, nil, nil)
      guard client >= 0 else { return nil }
      defer { close(client) }
      var timeout = timeval(tv_sec: 5, tv_usec: 0)
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      let banner = Array("SSH-2.0-OpenSSH_9.9\r\n".utf8)
      _ = write(client, banner, banner.count)
      var data: [UInt8] = []
      var buffer = [UInt8](repeating: 0, count: 4096)
      var start: Int?
      while true {
        if start == nil, let newline = data.firstIndex(of: 10) { start = newline + 1 }
        if let start, data.count >= start + 4 {
          let length = data[start..<(start + 4)].reduce(0) { $0 << 8 | Int($1) }
          if data.count >= start + 4 + length { return Self.parse(Array(data[(start + 4)...])) }
        }
        let count = read(client, &buffer, buffer.count)
        guard count > 0 else { return nil }
        data += buffer[..<count]
      }
    }

    /// `byte padding, byte 20 (KEXINIT), 16 cookie bytes, then name lists`: key exchange, host key, ciphers both ways,
    /// MACs both ways, compression both ways, languages both ways.
    private static func parse(_ packet: [UInt8]) -> [[String]]? {
      guard packet.count > 18, packet[1] == 20 else { return nil }
      var offset = 18
      var lists: [[String]] = []
      for _ in 0..<10 {
        guard offset + 4 <= packet.count else { return nil }
        let length = packet[offset..<(offset + 4)].reduce(0) { $0 << 8 | Int($1) }
        offset += 4
        guard offset + length <= packet.count else { return nil }
        lists.append(String(decoding: packet[offset..<(offset + length)], as: UTF8.self).split(separator: ",").map(String.init))
        offset += length
      }
      return lists
    }
  }
#endif
