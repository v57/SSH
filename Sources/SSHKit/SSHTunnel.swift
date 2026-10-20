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

  private let lock = NSLock()
  private var running = true
  private var closeReason: String?
  private var closedHandlers: [@Sendable (String?) -> Void] = []

  private var session: OpaquePointer?
  private var socketFD: SocketHandle = Sockets.invalid
  private let waker: PollWaker
  private let streams: SSHChannelStreams

  static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  private static let initialized: Bool = {
    libssh2_init(0)
    return true
  }()

  private init(server: SSHServer) {
    self.server = server
    let waker = PollWaker()
    self.waker = waker
    streams = SSHChannelStreams { waker.wake() }
  }

  /// Logs in.
  public static func open(server: SSHServer, timeout: TimeInterval = 20) async throws -> SSHTunnel {
    _ = initialized
    let tunnel = SSHTunnel(server: server)
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
      try setUp(timeout: timeout)
    } catch {
      teardown()
      lock.lock()
      running = false
      lock.unlock()
      ready.resume(throwing: error)
      return
    }
    ready.resume()
    loop()
    teardown()
  }

  private func setUp(timeout: TimeInterval) throws {
    socketFD = try Sockets.connect(host: server.host, port: server.port, timeout: timeout)
    guard let sess = libssh2_session_init_ex(nil, nil, nil, nil) else {
      throw SSHTunnelError.handshakeFailed("couldn't start an SSH session")
    }
    session = sess
    libssh2_session_set_blocking(sess, 0)
    if server.key?.kind == .rsa {
      _ = libssh2_session_method_pref(sess, LIBSSH2_METHOD_SIGN_ALGO, "rsa-sha2-256")
    }
    let deadline = Date().addingTimeInterval(timeout)
    try drive(deadline) { libssh2_session_handshake(sess, self.socketFD) } failure: {
      SSHTunnelError.handshakeFailed(self.lastError())
    }

    // Host key: trust on first use, refuse a changed key.
    guard let hash = libssh2_hostkey_hash(sess, LIBSSH2_HOSTKEY_HASH_SHA256) else {
      throw SSHTunnelError.handshakeFailed("the server sent no host key")
    }
    let digest = Data(bytes: hash, count: 32)
    hostKeyFingerprint = "SHA256:" + digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
    var keyLength = 0
    var keyType: Int32 = 0
    _ = libssh2_session_hostkey(sess, &keyLength, &keyType)
    hostKeyType = Self.hostKeyTypeName(keyType)
    if let known = server.knownFingerprint, !known.isEmpty, known != hostKeyFingerprint {
      throw SSHTunnelError.hostKeyChanged(expected: known, actual: hostKeyFingerprint)
    }

    try authenticate(sess, deadline: deadline)
    libssh2_keepalive_config(sess, 1, 30)
  }

  private func authenticate(_ sess: OpaquePointer, deadline: Date) throws {
    let user = server.user
    let userLength = UInt32(user.utf8.count)
    var methodsText = ""
    // Asking for the method list also detects servers that need no auth at all.
    var methods: UnsafeMutablePointer<CChar>?
    repeat {
      methods = libssh2_userauth_list(sess, user, userLength)
      if methods == nil && libssh2_session_last_errno(sess) == Self.eagain { waitSocket(sess) } else { break }
    } while Date() < deadline
    if let methods { methodsText = String(cString: methods) }
    if libssh2_userauth_authenticated(sess) == 1 { return }

    if let key = server.key, methodsText.isEmpty || methodsText.contains("publickey") {
      if try authenticateWithKey(sess, key: key, deadline: deadline) { return }
    }
    if let password = server.password, !password.isEmpty {
      if methodsText.isEmpty || methodsText.contains("password") {
        var rc: Int32 = 0
        repeat {
          rc = libssh2_userauth_password_ex(sess, user, userLength, password, UInt32(password.utf8.count), nil)
          if rc == Self.eagain { waitSocket(sess) }
        } while rc == Self.eagain && Date() < deadline
        if rc == 0 { return }
      }
      if methodsText.contains("keyboard-interactive") {
        let box = Unmanaged.passRetained(PasswordBox(password))
        defer { box.release() }
        libssh2_session_abstract(sess).pointee = box.toOpaque()
        var rc: Int32 = 0
        repeat {
          rc = libssh2_userauth_keyboard_interactive_ex(sess, user, userLength, keyboardInteractiveCallback)
          if rc == Self.eagain { waitSocket(sess) }
        } while rc == Self.eagain && Date() < deadline
        if rc == 0 { return }
      }
    }
    throw SSHTunnelError.authenticationFailed(methods: methodsText.replacingOccurrences(of: ",", with: ", "))
  }

  private func authenticateWithKey(_ sess: OpaquePointer, key: SSHKey, deadline: Date) throws -> Bool {
    let blob = try key.publicKeyBlob()
    let box = Unmanaged.passRetained(KeyBox(key))
    defer { box.release() }
    var abstract: UnsafeMutableRawPointer? = box.toOpaque()
    var rc: Int32 = 0
    repeat {
      rc = server.user.withCString { userPointer in
        blob.withUnsafeBufferPointer { blobPointer in
          libssh2_userauth_publickey(
            sess, userPointer, blobPointer.baseAddress, blob.count, signCallback, &abstract)
        }
      }
      if rc == Self.eagain { waitSocket(sess) }
    } while rc == Self.eagain && Date() < deadline
    return rc == 0
  }

  private func loop() {
    guard let sess = session else { return }
    var lastKeepalive = Date()
    while isAlive {
      // 1. Open the channels asked for, and move bytes.
      streams.pump(session: sess)

      // 2. Keepalive, and notice a dead transport.
      if Date().timeIntervalSince(lastKeepalive) > 5 {
        var next: Int32 = 0
        let rc = libssh2_keepalive_send(sess, &next)
        if rc < 0 && rc != Self.eagain {
          stop(reason: "The SSH connection dropped (\(lastError())).")
          break
        }
        lastKeepalive = Date()
      }
      if isTransportDead(sess) {
        stop(reason: "The SSH server closed the connection.")
        break
      }

      // 3. Sleep until the server sends something or the app does.
      var fds = [Sockets.descriptor(socketFD, events: Sockets.readable)]
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

  private func isTransportDead(_ sess: OpaquePointer) -> Bool {
    let errno = libssh2_session_last_errno(sess)
    return errno == LIBSSH2_ERROR_SOCKET_DISCONNECT || errno == LIBSSH2_ERROR_SOCKET_RECV
      || errno == LIBSSH2_ERROR_SOCKET_SEND
  }

  // MARK: Teardown

  private func teardown() {
    if let sess = session {
      libssh2_session_set_blocking(sess, 1)
      _ = libssh2_session_disconnect_ex(sess, SSH_DISCONNECT_BY_APPLICATION, "Closing tunnel", "")
      libssh2_session_free(sess)
      session = nil
    }
    if socketFD != Sockets.invalid {
      Sockets.close(socketFD)
      socketFD = Sockets.invalid
    }
    waker.close()
  }

  // MARK: Helpers

  private func drive(_ deadline: Date, _ op: () -> Int32, failure: () -> Error) throws {
    var rc = op()
    while rc == Self.eagain {
      if Date() > deadline { throw SSHTunnelError.handshakeFailed("timed out") }
      if let session { waitSocket(session) }
      rc = op()
    }
    if rc != 0 { throw failure() }
  }

  private func waitSocket(_ sess: OpaquePointer) {
    let directions = libssh2_session_block_directions(sess)
    var events: Int16 = 0
    if directions & LIBSSH2_SESSION_BLOCK_INBOUND != 0 { events |= Sockets.readable }
    if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 { events |= Sockets.writable }
    var descriptors = [Sockets.descriptor(socketFD, events: events == 0 ? Sockets.readable : events)]
    Sockets.poll(&descriptors, milliseconds: 100)
  }

  private func lastError() -> String {
    guard let session else { return "unknown error" }
    var message: UnsafeMutablePointer<CChar>?
    var length: Int32 = 0
    _ = libssh2_session_last_error(session, &message, &length, 0)
    return message.map { String(cString: $0) } ?? "unknown error"
  }

  static func hostKeyTypeName(_ type: Int32) -> String {
    switch type {
    case LIBSSH2_HOSTKEY_TYPE_RSA: "RSA"
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: "ECDSA P-256"
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: "ECDSA P-384"
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: "ECDSA P-521"
    case LIBSSH2_HOSTKEY_TYPE_ED25519: "Ed25519"
    default: "unknown"
    }
  }
}

// MARK: - libssh2 callbacks

private final class KeyBox {
  let key: SSHKey
  init(_ key: SSHKey) { self.key = key }
}

private final class PasswordBox {
  let password: String
  init(_ password: String) { self.password = password }
}

private let signCallback:
  @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<Int>?,
    UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UnsafeMutableRawPointer?>?
  ) -> Int32 = { _, sig, sigLength, data, dataLength, abstract in
    guard let sig, let sigLength, let data, let opaque = abstract?.pointee else { return -1 }
    let key = Unmanaged<KeyBox>.fromOpaque(opaque).takeUnretainedValue().key
    guard let signature = try? key.sign(Array(UnsafeBufferPointer(start: data, count: dataLength))) else {
      return -1
    }
    guard let buffer = malloc(signature.count)?.assumingMemoryBound(to: UInt8.self) else { return -1 }
    signature.withUnsafeBufferPointer { buffer.update(from: $0.baseAddress!, count: signature.count) }
    sig.pointee = buffer
    sigLength.pointee = signature.count
    return 0
  }

private let keyboardInteractiveCallback:
  @convention(c) (
    UnsafePointer<CChar>?, Int32, UnsafePointer<CChar>?, Int32, Int32,
    UnsafePointer<LIBSSH2_USERAUTH_KBDINT_PROMPT>?, UnsafeMutablePointer<LIBSSH2_USERAUTH_KBDINT_RESPONSE>?,
    UnsafeMutablePointer<UnsafeMutableRawPointer?>?
  ) -> Void = { _, _, _, _, count, _, responses, abstract in
    guard let responses, let opaque = abstract?.pointee else { return }
    let password = Unmanaged<PasswordBox>.fromOpaque(opaque).takeUnretainedValue().password
    for i in 0..<Int(count) {
      let bytes = Array(password.utf8)
      let buffer = malloc(bytes.count)!.assumingMemoryBound(to: CChar.self)
      bytes.withUnsafeBufferPointer { source in
        source.baseAddress!.withMemoryRebound(to: CChar.self, capacity: bytes.count) {
          buffer.update(from: $0, count: bytes.count)
        }
      }
      responses[i].text = buffer
      responses[i].length = UInt32(bytes.count)
    }
  }
