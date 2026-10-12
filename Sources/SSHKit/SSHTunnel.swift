import CLibssh2
import Darwin
import Foundation

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
      && a.key?.privateBytes == b.key?.privateBytes && a.knownFingerprint == b.knownFingerprint
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

/// A local port forward (`ssh -L 127.0.0.1:<random>:target:port`) over one SSH login.
///
/// libssh2 isn't thread-safe per session, so one dedicated thread owns the session
/// and every channel; a second thread only accepts local connections.
public final class SSHTunnel: @unchecked Sendable {
  public let server: SSHServer
  public let targetHost: String
  public let targetPort: Int
  public private(set) var localPort = 0
  public private(set) var hostKeyFingerprint = ""
  public private(set) var hostKeyType = ""

  private let lock = NSLock()
  private var running = true
  private var pendingFDs: [Int32] = []
  private var listenFD: Int32 = -1
  private var wakePipe: [Int32] = [-1, -1]
  private var closeReason: String?
  private var closedHandlers: [@Sendable (String?) -> Void] = []

  private var session: OpaquePointer?
  private var socketFD: Int32 = -1
  private var tunnels: [Tunnel] = []

  static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  private static let initialized: Bool = {
    libssh2_init(0)
    return true
  }()

  private init(server: SSHServer, targetHost: String, targetPort: Int) {
    self.server = server
    self.targetHost = targetHost
    self.targetPort = targetPort
  }

  /// Logs in and starts listening on 127.0.0.1 at a free port.
  public static func open(
    server: SSHServer, targetHost: String, targetPort: Int, timeout: TimeInterval = 20
  ) async throws -> SSHTunnel {
    _ = initialized
    let tunnel = SSHTunnel(server: server, targetHost: targetHost, targetPort: targetPort)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      let thread = Thread { tunnel.run(timeout: timeout, ready: continuation) }
      thread.name = "SSHTunnel \(server.host)"
      thread.qualityOfService = .userInitiated
      thread.start()
    }
    return tunnel
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
    let fd = listenFD
    listenFD = -1
    let handlers = closedHandlers
    closedHandlers = []
    lock.unlock()
    if fd >= 0 {
      Darwin.shutdown(fd, SHUT_RDWR)
      Darwin.close(fd)
    }
    wake()
    for handler in handlers { handler(reason) }
  }

  private func wake() {
    if wakePipe[1] >= 0 {
      var byte: UInt8 = 1
      _ = Darwin.write(wakePipe[1], &byte, 1)
    }
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
    socketFD = try Self.connectSocket(host: server.host, port: server.port, timeout: timeout)
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

    // Local listener.
    let (fd, port) = try Self.listen()
    listenFD = fd
    localPort = port
    if pipe(&wakePipe) == 0 {
      for end in wakePipe { _ = fcntl(end, F_SETFL, fcntl(end, F_GETFL) | O_NONBLOCK) }
    }
    let acceptThread = Thread { [weak self] in self?.acceptLoop(fd: fd) }
    acceptThread.name = "SSHTunnel accept"
    acceptThread.start()
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
      // 1. Channels for newly accepted connections.
      lock.lock()
      let fresh = pendingFDs
      pendingFDs.removeAll()
      lock.unlock()
      for fd in fresh {
        if let channel = openChannel(sess) {
          tunnels.append(Tunnel(channel: channel, fd: fd))
        } else {
          Darwin.close(fd)
        }
      }

      // 2. Move bytes.
      for tunnel in tunnels where !tunnel.closed { bridge(tunnel) }
      tunnels.removeAll { $0.closed }

      // 3. Keepalive, and notice a dead transport.
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

      // 4. Sleep until something happens.
      var fds: [pollfd] = [pollfd(fd: socketFD, events: Int16(POLLIN), revents: 0)]
      if tunnels.contains(where: { !$0.toChannel.isEmpty }) || libssh2_session_block_directions(sess) & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 {
        fds[0].events |= Int16(POLLOUT)
      }
      if wakePipe[0] >= 0 { fds.append(pollfd(fd: wakePipe[0], events: Int16(POLLIN), revents: 0)) }
      for tunnel in tunnels where !tunnel.localEOF {
        var events = Int16(POLLIN)
        if !tunnel.toLocal.isEmpty { events |= Int16(POLLOUT) }
        fds.append(pollfd(fd: tunnel.fd, events: events, revents: 0))
      }
      _ = poll(&fds, nfds_t(fds.count), 200)
      if wakePipe[0] >= 0 {
        var sink = [UInt8](repeating: 0, count: 64)
        while Darwin.read(wakePipe[0], &sink, sink.count) > 0 {}
      }
    }
    for tunnel in tunnels { closeTunnel(tunnel) }
    tunnels.removeAll()
  }

  private func isTransportDead(_ sess: OpaquePointer) -> Bool {
    let errno = libssh2_session_last_errno(sess)
    return errno == LIBSSH2_ERROR_SOCKET_DISCONNECT || errno == LIBSSH2_ERROR_SOCKET_RECV
      || errno == LIBSSH2_ERROR_SOCKET_SEND
  }

  private func openChannel(_ sess: OpaquePointer) -> OpaquePointer? {
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
      let channel = targetHost.withCString { host in
        libssh2_channel_direct_tcpip_ex(sess, host, Int32(targetPort), "127.0.0.1", 0)
      }
      if let channel { return channel }
      if libssh2_session_last_errno(sess) != Self.eagain { return nil }
      waitSocket(sess)
    }
    return nil
  }

  // MARK: Byte bridging

  private final class Tunnel {
    let channel: OpaquePointer
    var fd: Int32
    var toChannel: [UInt8] = []
    var toLocal: [UInt8] = []
    var localEOF = false
    var channelEOF = false
    var closed = false

    init(channel: OpaquePointer, fd: Int32) {
      self.channel = channel
      self.fd = fd
    }
  }

  private func bridge(_ tunnel: Tunnel) {
    var buffer = [UInt8](repeating: 0, count: 32 * 1024)
    // Remote → local.
    while !tunnel.channelEOF && tunnel.toLocal.count < 1 << 20 {
      let n = buffer.withUnsafeMutableBufferPointer { pointer in
        pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
          libssh2_channel_read_ex(tunnel.channel, 0, $0, pointer.count)
        }
      }
      if n > 0 {
        tunnel.toLocal += buffer[0..<Int(n)]
      } else if n == 0 {
        if libssh2_channel_eof(tunnel.channel) == 1 { tunnel.channelEOF = true }
        break
      } else {
        if Int32(n) != Self.eagain { tunnel.channelEOF = true }
        break
      }
    }
    if !tunnel.toLocal.isEmpty {
      let written = tunnel.toLocal.withUnsafeBytes { Darwin.write(tunnel.fd, $0.baseAddress, $0.count) }
      if written > 0 {
        tunnel.toLocal.removeFirst(written)
      } else if written < 0 && errno != EAGAIN && errno != EWOULDBLOCK {
        closeTunnel(tunnel)
        return
      }
    }
    // Local → remote.
    if !tunnel.localEOF && tunnel.toChannel.count < 1 << 20 {
      let n = buffer.withUnsafeMutableBytes { Darwin.recv(tunnel.fd, $0.baseAddress, $0.count, 0) }
      if n > 0 {
        tunnel.toChannel += buffer[0..<n]
      } else if n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) {
        tunnel.localEOF = true
      }
    }
    while !tunnel.toChannel.isEmpty {
      let written = tunnel.toChannel.withUnsafeBufferPointer { pointer in
        pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
          libssh2_channel_write_ex(tunnel.channel, 0, $0, pointer.count)
        }
      }
      if written > 0 {
        tunnel.toChannel.removeFirst(Int(written))
      } else if Int32(written) == Self.eagain {
        break
      } else {
        closeTunnel(tunnel)
        return
      }
    }
    if tunnel.localEOF && tunnel.toChannel.isEmpty { _ = libssh2_channel_send_eof(tunnel.channel) }
    if tunnel.channelEOF && tunnel.toLocal.isEmpty {
      if tunnel.localEOF {
        closeTunnel(tunnel)
      } else {
        Darwin.shutdown(tunnel.fd, SHUT_WR)
        // The remote side is done; when the local side hangs up too, the tunnel ends.
        tunnel.localEOF = tunnel.localEOF || isPeerClosed(tunnel.fd)
        if tunnel.localEOF { closeTunnel(tunnel) }
      }
    }
  }

  private func isPeerClosed(_ fd: Int32) -> Bool {
    var probe: UInt8 = 0
    let n = Darwin.recv(fd, &probe, 1, MSG_PEEK)
    return n == 0
  }

  private func closeTunnel(_ tunnel: Tunnel) {
    guard !tunnel.closed else { return }
    tunnel.closed = true
    _ = libssh2_channel_close(tunnel.channel)
    _ = libssh2_channel_free(tunnel.channel)
    if tunnel.fd >= 0 {
      Darwin.close(tunnel.fd)
      tunnel.fd = -1
    }
  }

  // MARK: Accept thread

  private func acceptLoop(fd: Int32) {
    while isAlive {
      let client = Darwin.accept(fd, nil, nil)
      if client < 0 {
        if errno == EINTR { continue }
        break
      }
      _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK)
      var one: Int32 = 1
      setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
      setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
      lock.lock()
      pendingFDs.append(client)
      lock.unlock()
      wake()
    }
  }

  // MARK: Teardown

  private func teardown() {
    for tunnel in tunnels { closeTunnel(tunnel) }
    tunnels.removeAll()
    lock.lock()
    let leftovers = pendingFDs
    pendingFDs.removeAll()
    lock.unlock()
    for fd in leftovers { Darwin.close(fd) }
    if let sess = session {
      libssh2_session_set_blocking(sess, 1)
      _ = libssh2_session_disconnect_ex(sess, SSH_DISCONNECT_BY_APPLICATION, "Closing tunnel", "")
      libssh2_session_free(sess)
      session = nil
    }
    if socketFD >= 0 {
      Darwin.close(socketFD)
      socketFD = -1
    }
    for end in wakePipe where end >= 0 { Darwin.close(end) }
    wakePipe = [-1, -1]
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
    if directions & LIBSSH2_SESSION_BLOCK_INBOUND != 0 { events |= Int16(POLLIN) }
    if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 { events |= Int16(POLLOUT) }
    var pfd = pollfd(fd: socketFD, events: events == 0 ? Int16(POLLIN) : events, revents: 0)
    _ = poll(&pfd, 1, 100)
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

  static func connectSocket(host: String, port: Int, timeout: TimeInterval) throws -> Int32 {
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = SOCK_STREAM
    var info: UnsafeMutablePointer<addrinfo>?
    let rc = getaddrinfo(host, String(port), &hints, &info)
    guard rc == 0, let first = info else {
      throw SSHTunnelError.connectFailed("the host name \(host) couldn't be found")
    }
    defer { freeaddrinfo(first) }
    var lastError = "nothing answered"
    var candidate: UnsafeMutablePointer<addrinfo>? = first
    while let address = candidate {
      candidate = address.pointee.ai_next
      let fd = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
      if fd < 0 { continue }
      var one: Int32 = 1
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
      _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
      if connect(fd, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 { return fd }
      if errno == EINPROGRESS {
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        if poll(&pfd, 1, Int32(timeout * 1000)) > 0 {
          var error: Int32 = 0
          var length = socklen_t(MemoryLayout<Int32>.size)
          getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
          if error == 0 { return fd }
          lastError = error == ECONNREFUSED ? "connection refused (is SSH on?)" : String(cString: strerror(error))
        } else {
          lastError = "timed out"
        }
      } else {
        lastError = String(cString: strerror(errno))
      }
      Darwin.close(fd)
    }
    throw SSHTunnelError.connectFailed(lastError)
  }

  static func listen() throws -> (Int32, Int) {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { throw SSHTunnelError.forwardFailed("no socket") }
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = 0
    let bound = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    }
    guard bound == 0, Darwin.listen(fd, 32) == 0 else {
      Darwin.close(fd)
      throw SSHTunnelError.forwardFailed("couldn't listen locally")
    }
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
    }
    return (fd, Int(UInt16(bigEndian: address.sin_port)))
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
