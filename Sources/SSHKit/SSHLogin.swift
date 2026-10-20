import CLibssh2
import Foundation

/// One libssh2 session from the TCP connection to a logged-in user: handshake, host key check, key or password
/// login. `SSHTunnel` and `SFTPClient` both log in through it, so they check host keys and authenticate the same way.
///
/// libssh2 isn't thread-safe per session: everything here runs on the thread that owns the session. The session is
/// non-blocking; `waitSocket` sleeps until libssh2 can go on.
final class SSHLogin {
  let server: SSHServer
  private(set) var session: OpaquePointer?
  private(set) var socket: SocketHandle = Sockets.invalid
  private(set) var hostKeyFingerprint = ""
  private(set) var hostKeyType = ""
  /// The jump host's login and the channel through it, when the server is reached through one.
  private let jump: SSHJump?

  static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  static let initialized: Bool = {
    libssh2_init(0)
    return true
  }()

  init(server: SSHServer, jump: SSHJump?) {
    _ = Self.initialized
    self.server = server
    self.jump = jump
  }

  /// Connects (or takes the jump host's channel), shakes hands, checks the host key and logs in. On failure the
  /// caller still calls `teardown`.
  func connect(timeout: TimeInterval) throws {
    if let jump {
      socket = jump.takeSocket()
    } else {
      do {
        socket = try Sockets.connect(host: server.host, port: server.port, timeout: timeout)
      } catch {
        throw SSHTunnelError.connectFailed(Self.describe(error, host: server.host))
      }
    }
    guard let sess = libssh2_session_init_ex(nil, nil, nil, nil) else {
      throw SSHTunnelError.handshakeFailed("couldn't start an SSH session")
    }
    session = sess
    libssh2_session_set_blocking(sess, 0)
    if server.key?.kind == .rsa {
      _ = libssh2_session_method_pref(sess, LIBSSH2_METHOD_SIGN_ALGO, "rsa-sha2-256")
    }
    let deadline = Date().addingTimeInterval(timeout)
    try drive(deadline) { libssh2_session_handshake(sess, self.socket) } failure: {
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
  }

  private func authenticate(_ sess: OpaquePointer, deadline: Date) throws {
    let user = server.user
    let userLength = UInt32(user.utf8.count)
    var methodsText = ""
    // Asking for the method list also detects servers that need no auth at all.
    var methods: UnsafeMutablePointer<CChar>?
    repeat {
      methods = libssh2_userauth_list(sess, user, userLength)
      if methods == nil && libssh2_session_last_errno(sess) == Self.eagain { waitSocket() } else { break }
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
          if rc == Self.eagain { waitSocket() }
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
          if rc == Self.eagain { waitSocket() }
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
      if rc == Self.eagain { waitSocket() }
    } while rc == Self.eagain && Date() < deadline
    return rc == 0
  }

  // MARK: Teardown

  /// Says goodbye, frees the session, closes the socket and the jump host's login.
  func teardown(reason: String = "Closing") {
    if let sess = session {
      libssh2_session_set_blocking(sess, 1)
      libssh2_session_set_timeout(sess, 2000)
      _ = libssh2_session_disconnect_ex(sess, SSH_DISCONNECT_BY_APPLICATION, reason, "")
      libssh2_session_free(sess)
      session = nil
    }
    if socket != Sockets.invalid {
      Sockets.close(socket)
      socket = Sockets.invalid
    }
    jump?.close()
  }

  // MARK: Helpers

  var isTransportDead: Bool {
    guard let session else { return true }
    let errno = libssh2_session_last_errno(session)
    return errno == LIBSSH2_ERROR_SOCKET_DISCONNECT || errno == LIBSSH2_ERROR_SOCKET_RECV
      || errno == LIBSSH2_ERROR_SOCKET_SEND
  }

  func drive(_ deadline: Date, _ op: () -> Int32, failure: () -> Error) throws {
    var rc = op()
    while rc == Self.eagain {
      if Date() > deadline { throw SSHTunnelError.handshakeFailed("timed out") }
      waitSocket()
      rc = op()
    }
    if rc != 0 { throw failure() }
  }

  /// Sleeps (up to `milliseconds`) until the socket is ready the way libssh2 last wanted it.
  func waitSocket(milliseconds: Int32 = 100) {
    guard let session else { return }
    let directions = libssh2_session_block_directions(session)
    var events: Int16 = 0
    if directions & LIBSSH2_SESSION_BLOCK_INBOUND != 0 { events |= Sockets.readable }
    if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 { events |= Sockets.writable }
    var descriptors = [Sockets.descriptor(socket, events: events == 0 ? Sockets.readable : events)]
    Sockets.poll(&descriptors, milliseconds: milliseconds)
  }

  func lastError() -> String {
    guard let session else { return "unknown error" }
    var message: UnsafeMutablePointer<CChar>?
    var length: Int32 = 0
    _ = libssh2_session_last_error(session, &message, &length, 0)
    return message.map { String(cString: $0) } ?? "unknown error"
  }

  static func describe(_ error: SocketError, host: String) -> String {
    switch error {
    case .hostNotFound: "the host name \(host) couldn't be found"
    case .timedOut: "timed out"
    case .failed(let code, let message): code == Sockets.connectionRefused ? "connection refused (is SSH on?)" : message
    }
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
