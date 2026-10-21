import CLibssh2
import Foundation

/// One command on the SSH server (`ssh host command`): its output as it arrives, its exit status, and Stop. It logs in
/// like `SSHTunnel` and `SFTPClient` (`SSHLogin`: host key check, key or password), on its own session and thread.
///
/// The command runs on a pseudo-terminal, so programs flush their output line by line and show progress, and closing
/// the channel (Stop) hangs it up. Standard error arrives mixed into the output, as on a terminal.
public final class SSHCommand: @unchecked Sendable {
  public let server: SSHServer
  public let command: String
  public private(set) var hostKeyFingerprint = ""

  private let lock = NSLock()
  private var stopped = false
  private let login: SSHLogin

  private static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  public init(server: SSHServer, command: String) {
    self.server = server
    self.command = command
    login = SSHLogin(server: server, jump: nil)
  }

  /// Logs in, runs the command and returns its exit status once it ends (nil when the server sent none, as for a
  /// command ended by Stop or a signal). `onOutput` gets each chunk of output on the command's thread.
  public func run(timeout: TimeInterval = 20, onOutput: @escaping @Sendable (Data) -> Void) async throws -> Int32? {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int32?, Error>) in
      let thread = Thread { [self] in
        do {
          continuation.resume(returning: try runNow(timeout: timeout, onOutput: onOutput))
        } catch {
          continuation.resume(throwing: error)
        }
        login.teardown(reason: "Command finished")
      }
      thread.name = "SSHCommand \(server.host)"
      thread.qualityOfService = .userInitiated
      thread.start()
    }
  }

  /// Hangs the command up: `run` returns soon after.
  public func stop() {
    lock.withLock { stopped = true }
  }

  private var isStopped: Bool { lock.withLock { stopped } }

  // MARK: Owner thread

  private func runNow(timeout: TimeInterval, onOutput: @Sendable (Data) -> Void) throws -> Int32? {
    try login.connect(timeout: timeout)
    hostKeyFingerprint = login.hostKeyFingerprint
    guard let session = login.session else { throw SSHTunnelError.closed }
    libssh2_keepalive_config(session, 0, 30)
    let deadline = Date().addingTimeInterval(timeout)
    let channel = try open(session, deadline: deadline)
    defer {
      _ = drain { libssh2_channel_close(channel) }
      libssh2_channel_free(channel)
    }
    try request("a terminal", deadline) {
      libssh2_channel_request_pty_ex(channel, "xterm", 5, nil, 0, 400, 50, 0, 0)
    }
    try request("the command", deadline) {
      libssh2_channel_process_startup(channel, "exec", 4, command, UInt32(command.utf8.count))
    }

    var buffer = [CChar](repeating: 0, count: 32 * 1024)
    var lastKeepalive = Date()
    while !isStopped {
      let count = libssh2_channel_read_ex(channel, 0, &buffer, buffer.count)
      if count > 0 {
        onOutput(Data(bytes: buffer, count: count))
        continue
      }
      if count < 0 && Int32(count) != Self.eagain {
        throw SSHTunnelError.forwardFailed("the command's output broke off (\(login.lastError()))")
      }
      if libssh2_channel_eof(channel) != 0 { break }
      if Date().timeIntervalSince(lastKeepalive) > 15 {
        var next: Int32 = 0
        _ = libssh2_keepalive_send(session, &next)
        lastKeepalive = Date()
      }
      if login.isTransportDead { throw SSHTunnelError.closed }
      login.waitSocket()
    }
    if isStopped { return nil }
    _ = drain { libssh2_channel_wait_eof(channel) }
    _ = drain { libssh2_channel_close(channel) }
    _ = drain { libssh2_channel_wait_closed(channel) }
    var signal: UnsafeMutablePointer<CChar>?
    var length = 0
    _ = libssh2_channel_get_exit_signal(channel, &signal, &length, nil, nil, nil, nil)
    if let signal {
      free(signal)
      return nil
    }
    return libssh2_channel_get_exit_status(channel)
  }

  private func open(_ session: OpaquePointer, deadline: Date) throws -> OpaquePointer {
    while true {
      if let channel = libssh2_channel_open_ex(
        session, "session", 7, UInt32(2 * 1024 * 1024), UInt32(32 * 1024), nil, 0)
      {
        return channel
      }
      guard libssh2_session_last_errno(session) == Self.eagain, Date() < deadline, !isStopped else {
        throw SSHTunnelError.forwardFailed("the server didn't open a session (\(login.lastError()))")
      }
      login.waitSocket()
    }
  }

  private func request(_ what: String, _ deadline: Date, _ op: () -> Int32) throws {
    var rc = op()
    while rc == Self.eagain && Date() < deadline && !isStopped {
      login.waitSocket()
      rc = op()
    }
    guard rc == 0 else { throw SSHTunnelError.forwardFailed("the server refused \(what) (\(login.lastError()))") }
  }

  /// Repeats a closing call while libssh2 would block, for a moment at most.
  private func drain(_ op: () -> Int32) -> Int32 {
    let deadline = Date().addingTimeInterval(2)
    var rc = op()
    while rc == Self.eagain && Date() < deadline {
      login.waitSocket()
      rc = op()
    }
    return rc
  }
}
