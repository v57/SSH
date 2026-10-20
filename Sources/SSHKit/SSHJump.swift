import Foundation
import WireKit

/// The way to a server through a jump host (`ssh -J`): a login to the jump host, and a `direct-tcpip` channel from
/// it to the server. libssh2 wants a socket for the server's session, so the channel's bytes cross a socket pair
/// inside this process: one end goes to libssh2, two threads move bytes between the other end and the channel.
/// Nothing listens on a port.
final class SSHJump: @unchecked Sendable {
  let tunnel: SSHTunnel
  private let channel: WireChannel
  private let lock = NSLock()
  private var sessionEnd: SocketHandle
  private let bridgeEnd: SocketHandle
  private let threads = DispatchGroup()
  private var closed = false

  var hostKeyFingerprint: String { tunnel.hostKeyFingerprint }

  private init(tunnel: SSHTunnel, channel: WireChannel, sessionEnd: SocketHandle, bridgeEnd: SocketHandle) {
    self.tunnel = tunnel
    self.channel = channel
    self.sessionEnd = sessionEnd
    self.bridgeEnd = bridgeEnd
  }

  static func open(to server: SSHServer, through jump: SSHServer, timeout: TimeInterval) async throws -> SSHJump {
    #if os(Windows)
      throw SSHTunnelError.connectFailed("going through a jump host isn't supported on Windows yet")
    #else
      let tunnel = try await SSHTunnel.open(server: jump, timeout: timeout)
      let channel: WireChannel
      do {
        channel = try await tunnel.open(host: server.host, port: server.port, timeout: timeout)
      } catch {
        tunnel.close()
        throw SSHTunnelError.connectFailed("the jump host \(jump.host) couldn't reach \(server.host):\(server.port)")
      }
      var ends: [Int32] = [-1, -1]
      guard socketpair(AF_UNIX, SOCK_STREAM, 0, &ends) == 0 else {
        channel.close()
        tunnel.close()
        throw SSHTunnelError.connectFailed("couldn't make a socket pair (\(Sockets.describe(Sockets.lastError)))")
      }
      for end in ends { Sockets.setOption(end, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1) }
      // libssh2's end is non-blocking, like a TCP socket from `Sockets.connect`; the bridge's blocks.
      Sockets.setNonBlocking(ends[0])
      let jump = SSHJump(tunnel: tunnel, channel: channel, sessionEnd: ends[0], bridgeEnd: ends[1])
      jump.start(name: server.host)
      return jump
    #endif
  }

  /// The socket for libssh2; the session owns it from now on.
  func takeSocket() -> SocketHandle {
    lock.lock()
    defer { lock.unlock() }
    let socket = sessionEnd
    sessionEnd = Sockets.invalid
    return socket
  }

  /// Ends the channel and the jump host's login (after the session closed its socket).
  func close() {
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
    #if !os(Windows)
      shutdown(bridgeEnd, SHUT_RDWR)
    #endif
    channel.close()
    tunnel.close()
    let bridgeEnd = bridgeEnd
    threads.notify(queue: .global()) { Sockets.close(bridgeEnd) }
  }

  #if !os(Windows)
    private func start(name: String) {
      let channel = channel
      let socket = bridgeEnd
      // Session → channel.
      threads.enter()
      let up = Thread { [threads] in
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
          let n = buffer.withUnsafeMutableBytes { Darwin.read(socket, $0.baseAddress, $0.count) }
          if n < 0 && errno == EINTR { continue }
          guard n > 0 else { break }
          let bytes = Array(buffer[0..<n])
          guard Self.blocking({ try await channel.send(bytes) }) != nil else { break }
        }
        channel.close()
        threads.leave()
      }
      // Channel → session.
      threads.enter()
      let down = Thread { [threads] in
        while let bytes = Self.blocking({ try await channel.receive() }) {
          var offset = 0
          while offset < bytes.count {
            let n = bytes.withUnsafeBytes { Darwin.write(socket, $0.baseAddress! + offset, bytes.count - offset) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            offset += n
          }
          if offset < bytes.count { break }
        }
        shutdown(socket, SHUT_WR)
        threads.leave()
      }
      for (thread, direction) in [(up, "up"), (down, "down")] {
        thread.name = "SSHJump \(name) \(direction)"
        thread.qualityOfService = .userInitiated
        thread.start()
      }
    }

    /// Runs an async channel call from a bridge thread and waits for it; nil when it throws.
    private static func blocking<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) -> T? {
      let semaphore = DispatchSemaphore(value: 0)
      let result = ResultBox<T>()
      Task {
        result.value = try? await body()
        semaphore.signal()
      }
      semaphore.wait()
      return result.value
    }
  #endif
}

private final class ResultBox<T>: @unchecked Sendable {
  var value: T?
}
