import CLibssh2
import Foundation
import WireKit

/// Where and how to log in over SSH.
public struct SSHServer: Sendable, Hashable {
  public var host: String
  public var port: Int
  public var user: String
  public var password: String?
  public var key: SSHKey?
  /// The `SHA256:…` fingerprint seen before. `nil` trusts the first key the server shows.
  public var knownFingerprint: String?

  public init(
    host: String, port: Int = 22, user: String, password: String? = nil, key: SSHKey? = nil,
    knownFingerprint: String? = nil
  ) {
    self.host = host
    self.port = port
    self.user = user
    self.password = password
    self.key = key
    self.knownFingerprint = knownFingerprint
  }

  public static func == (a: SSHServer, b: SSHServer) -> Bool {
    a.host == b.host && a.port == b.port && a.user == b.user && a.password == b.password
      && a.key?.privateBytes == b.key?.privateBytes
      && (try? a.key?.publicKeyBlob()) == (try? b.key?.publicKeyBlob()) && a.knownFingerprint == b.knownFingerprint
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(host)
    hasher.combine(port)
    hasher.combine(user)
  }
}

public enum SSHTunnelError: Error, LocalizedError, Sendable, Equatable {
  case connectFailed(String)
  case handshakeFailed(String)
  case hostKeyChanged(expected: String, actual: String)
  case authenticationFailed(methods: String)
  case forwardFailed(String)
  case closed

  public var errorDescription: String? {
    switch self {
    case .connectFailed(let detail): "Couldn't reach the SSH server: \(detail)"
    case .handshakeFailed(let detail): "The SSH handshake failed: \(detail)"
    case .hostKeyChanged(let expected, let actual):
      "The SSH server's identity changed (was \(expected), now \(actual)). If you expected this, forget the saved host key and connect again."
    case .authenticationFailed(let methods):
      "The SSH server didn't accept the key or password." + (methods.isEmpty ? "" : " It allows: \(methods).")
    case .forwardFailed(let detail): "The SSH server refused the tunnel: \(detail)"
    case .closed: "The SSH tunnel closed."
    }
  }
}

/// One SSH login whose `direct-tcpip` channels carry database connections (`dialer`): `ssh -L`, without the local
/// port. Nothing listens on this device, so other apps and users can't reach the database through the tunnel.
///
/// libssh2 isn't thread-safe per session, so one dedicated thread owns the session and every channel.
public final class SSHTunnel: @unchecked Sendable {
  public let server: SSHServer
  public private(set) var hostKeyFingerprint = ""
  public private(set) var hostKeyType = ""
  /// The jump host's key, when the tunnel goes through one.
  public private(set) var jumpHostKeyFingerprint: String?

  private let lock = NSLock()
  private var running = true
  private var closeReason: String?
  private var closedHandlers: [@Sendable (String?) -> Void] = []

  private let login: SSHLogin
  private let waker: PollWaker
  private let streams: SSHChannelStreams

  static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  private init(server: SSHServer, jump: SSHJump?) {
    self.server = server
    login = SSHLogin(server: server, jump: jump)
    jumpHostKeyFingerprint = jump?.hostKeyFingerprint
    let waker = PollWaker()
    self.waker = waker
    streams = SSHChannelStreams { waker.wake() }
  }

  /// Logs in, through `jump` first if there is one (`ssh -J`: the jump host's own login, then a channel from it to
  /// `server`, which checks the server's host key and logs in end to end).
  public static func open(server: SSHServer, through jump: SSHServer? = nil, timeout: TimeInterval = 20) async throws
    -> SSHTunnel
  {
    var hop: SSHJump?
    if let jump { hop = try await SSHJump.open(to: server, through: jump, timeout: timeout) }
    let tunnel = SSHTunnel(server: server, jump: hop)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      let thread = Thread { tunnel.run(timeout: timeout, ready: continuation) }
      thread.name = "SSHTunnel \(server.host)"
      thread.qualityOfService = .userInitiated
      thread.start()
    }
    return tunnel
  }

  /// Connections through the tunnel, each on its own channel: `host` is as the SSH server sees it ("127.0.0.1" is
  /// the server itself).
  public var dialer: WireDialer { streams.dialer }

  /// A stream to `host:port` through the tunnel.
  public func open(host: String, port: Int, timeout: TimeInterval = 15) async throws -> WireChannel {
    try await streams.open(host: host, port: port, timeout: timeout)
  }

  public var isAlive: Bool {
    lock.lock()
    defer { lock.unlock() }
    return running
  }

  /// Called once, on any thread, when the tunnel stops (with a reason if it broke).
  public func onClosed(_ handler: @escaping @Sendable (String?) -> Void) {
    lock.lock()
    if running {
      closedHandlers.append(handler)
      lock.unlock()
    } else {
      let reason = closeReason
      lock.unlock()
      handler(reason)
    }
  }

  public func close() {
    stop(reason: nil)
  }

  private func stop(reason: String?) {
    lock.lock()
    guard running else {
      lock.unlock()
      return
    }
    running = false
    closeReason = reason
    let handlers = closedHandlers
    closedHandlers = []
    lock.unlock()
    waker.wake()
    for handler in handlers { handler(reason) }
  }

  // MARK: - Owner thread

  private func run(timeout: TimeInterval, ready: CheckedContinuation<Void, Error>) {
    do {
      try login.connect(timeout: timeout)
      hostKeyFingerprint = login.hostKeyFingerprint
      hostKeyType = login.hostKeyType
      if let session = login.session { libssh2_keepalive_config(session, 1, 30) }
    } catch {
      hostKeyFingerprint = login.hostKeyFingerprint
      hostKeyType = login.hostKeyType
      login.teardown(reason: "Closing tunnel")
      waker.close()
      lock.lock()
      running = false
      lock.unlock()
      ready.resume(throwing: error)
      return
    }
    ready.resume()
    loop()
    login.teardown(reason: "Closing tunnel")
    waker.close()
  }

  private func loop() {
    guard let sess = login.session else { return }
    var lastKeepalive = Date()
    while isAlive {
      // 1. Open the channels asked for, and move bytes.
      streams.pump(session: sess)

      // 2. Keepalive, and notice a dead transport.
      if Date().timeIntervalSince(lastKeepalive) > 5 {
        var next: Int32 = 0
        let rc = libssh2_keepalive_send(sess, &next)
        if rc < 0 && rc != Self.eagain {
          stop(reason: "The SSH connection dropped (\(login.lastError())).")
          break
        }
        lastKeepalive = Date()
      }
      if login.isTransportDead {
        stop(reason: "The SSH server closed the connection.")
        break
      }

      // 3. Sleep until the server sends something or the app does.
      var fds = [Sockets.descriptor(login.socket, events: Sockets.readable)]
      if streams.wantsSocketOut || libssh2_session_block_directions(sess) & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 {
        fds[0].events |= Sockets.writable
      }
      if waker.isValid { fds.append(Sockets.descriptor(waker.fd, events: Sockets.readable)) }
      Sockets.poll(&fds, milliseconds: 200)
      waker.drain()
    }
    lock.lock()
    let reason = closeReason ?? SSHTunnelError.closed.localizedDescription
    lock.unlock()
    streams.closeAll(reason: reason)
  }
}
