import CLibssh2
import Foundation

/// The way to a server through a jump host (`ssh -J`): a login to the jump host, and a `direct-tcpip` channel from
/// it to the server. libssh2 wants a socket for the server's session, so the channel's bytes cross a socket pair
/// inside this process: one end goes to the server's session, and the jump host's own thread moves bytes between the
/// other end and the channel. Nothing listens on a port.
///
/// The server's login (`SSHLogin(server:jump:)`) takes the socket and closes the jump when it's torn down.
public final class SSHJump: @unchecked Sendable {
  private let login: SSHLogin
  private let lock = NSLock()
  private var sessionEnd: SocketHandle = Sockets.invalid
  private var bridgeEnd: SocketHandle = Sockets.invalid
  private let waker = PollWaker()
  private var closed = false

  private static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  /// The jump host's key, once logged in.
  public private(set) var hostKeyFingerprint = ""

  private init(jump: SSHServer) {
    login = SSHLogin(server: jump, jump: nil)
  }

  /// Logs in to `jump` and opens a channel from it to `server`'s SSH port, on a thread of its own.
  public static func open(to server: SSHServer, through jump: SSHServer, timeout: TimeInterval) async throws -> SSHJump {
    #if os(Windows)
      throw SSHTunnelError.connectFailed("going through a jump host isn't supported on Windows yet")
    #else
      let hop = SSHJump(jump: jump)
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        let thread = Thread { hop.run(to: server, timeout: timeout, ready: continuation) }
        thread.name = "SSHJump \(jump.host) → \(server.host)"
        thread.qualityOfService = .userInitiated
        thread.start()
      }
      return hop
    #endif
  }

  /// The socket for libssh2; the session owns it from now on.
  public func takeSocket() -> SocketHandle {
    lock.lock()
    defer { lock.unlock() }
    let socket = sessionEnd
    sessionEnd = Sockets.invalid
    return socket
  }

  /// Ends the channel and the jump host's login (after the session closed its socket).
  public func close() {
    lock.lock()
    guard !closed else {
      lock.unlock()
      return
    }
    closed = true
    let unused = sessionEnd
    sessionEnd = Sockets.invalid
    lock.unlock()
    if unused != Sockets.invalid { Sockets.close(unused) }
    waker.wake()
  }

  private var isClosed: Bool { lock.withLock { closed } }

  // MARK: - Owner thread

  #if !os(Windows)
    private func run(to server: SSHServer, timeout: TimeInterval, ready: CheckedContinuation<Void, Error>) {
      let channel: OpaquePointer
      do {
        try login.connect(timeout: timeout)
        hostKeyFingerprint = login.hostKeyFingerprint
        channel = try openChannel(to: server, deadline: Date().addingTimeInterval(timeout))
        try makeSocketPair()
      } catch {
        login.teardown(reason: "Closing jump")
        waker.close()
        ready.resume(throwing: error)
        return
      }
      ready.resume()
      pump(channel)
      _ = libssh2_channel_close(channel)
      _ = libssh2_channel_free(channel)
      login.teardown(reason: "Closing jump")
      Sockets.close(bridgeEnd)
      waker.close()
    }

    private func openChannel(to server: SSHServer, deadline: Date) throws -> OpaquePointer {
      guard let session = login.session else { throw SSHTunnelError.closed }
      while true {
        let channel = server.host.withCString { host in
          libssh2_channel_direct_tcpip_ex(session, host, Int32(server.port), "127.0.0.1", 0)
        }
        if let channel { return channel }
        guard libssh2_session_last_errno(session) == Self.eagain, Date() < deadline else {
          throw SSHTunnelError.connectFailed(
            "the jump host \(login.server.host) couldn't reach \(server.host):\(server.port)")
        }
        login.waitSocket()
      }
    }

    private func makeSocketPair() throws {
      var ends: [Int32] = [-1, -1]
      #if canImport(Darwin)
        let type = SOCK_STREAM
      #else
        let type = Int32(SOCK_STREAM.rawValue)
      #endif
      guard socketpair(AF_UNIX, type, 0, &ends) == 0 else {
        throw SSHTunnelError.connectFailed("couldn't make a socket pair (\(Sockets.describe(Sockets.lastError)))")
      }
      for end in ends {
        #if canImport(Darwin)
          Sockets.setOption(end, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
        #endif
        // Both ends are non-blocking, like a TCP socket from `Sockets.connect`.
        Sockets.setNonBlocking(end)
      }
      lock.withLock {
        sessionEnd = ends[0]
        bridgeEnd = ends[1]
      }
    }

    /// Moves bytes between the bridge's end of the socket pair and the channel until either side ends or `close`.
    private func pump(_ channel: OpaquePointer) {
      guard let session = login.session else { return }
      libssh2_keepalive_config(session, 0, 30)
      var toChannel: [UInt8] = []
      var toSocket: [UInt8] = []
      var buffer = [UInt8](repeating: 0, count: 32 * 1024)
      var sessionEnded = false
      var lastKeepalive = Date()
      loop: while !isClosed {
        // Whether any bytes moved this round: libssh2 may hold more than the socket shows, so poll only when idle.
        var moved = false
        // The server's session → the channel.
        if toChannel.isEmpty && !sessionEnded {
          switch buffer.withUnsafeMutableBytes({ Sockets.receive(bridgeEnd, into: $0) }) {
          case .bytes(let count):
            toChannel = Array(buffer[0..<count])
            moved = true
          case .wouldBlock: break
          case .closed, .failed: sessionEnded = true
          }
        }
        while !toChannel.isEmpty {
          let written = toChannel.withUnsafeBufferPointer { pointer in
            pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
              libssh2_channel_write_ex(channel, 0, $0, pointer.count)
            }
          }
          if written > 0 {
            toChannel.removeFirst(Int(written))
            moved = true
          } else if Int32(written) == Self.eagain {
            break
          } else {
            break loop
          }
        }
        // The session closed its socket: it's done with the server.
        if sessionEnded && toChannel.isEmpty { break }

        // The channel → the server's session.
        if toSocket.isEmpty {
          let count = buffer.withUnsafeMutableBufferPointer { pointer in
            pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
              libssh2_channel_read_ex(channel, 0, $0, pointer.count)
            }
          }
          if count > 0 {
            toSocket = Array(buffer[0..<Int(count)])
            moved = true
          } else if count < 0 && Int32(count) != Self.eagain {
            break
          } else if libssh2_channel_eof(channel) == 1 {
            // The server hung up; its session reads the end.
            Sockets.shutdownWrite(bridgeEnd)
            break
          }
        }
        if !toSocket.isEmpty {
          switch toSocket.withUnsafeBytes({ Sockets.send(bridgeEnd, $0) }) {
          case .bytes(let count):
            toSocket.removeFirst(count)
            if count > 0 { moved = true }
          case .wouldBlock: break
          case .closed, .failed: break loop
          }
        }

        if Date().timeIntervalSince(lastKeepalive) > 15 {
          var next: Int32 = 0
          _ = libssh2_keepalive_send(session, &next)
          lastKeepalive = Date()
        }
        if login.isTransportDead { break }
        if moved { continue }

        // Sleep until the jump host, the server's session or `close` has something.
        var fds = [Sockets.descriptor(login.socket, events: Sockets.readable)]
        if !toChannel.isEmpty || libssh2_session_block_directions(session) & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 {
          fds[0].events |= Sockets.writable
        }
        var bridgeEvents: Int16 = 0
        if toChannel.isEmpty && !sessionEnded { bridgeEvents |= Sockets.readable }
        if !toSocket.isEmpty { bridgeEvents |= Sockets.writable }
        if bridgeEvents != 0 { fds.append(Sockets.descriptor(bridgeEnd, events: bridgeEvents)) }
        if waker.isValid { fds.append(Sockets.descriptor(waker.fd, events: Sockets.readable)) }
        Sockets.poll(&fds, milliseconds: 200)
        waker.drain()
      }
    }
  #endif
}
