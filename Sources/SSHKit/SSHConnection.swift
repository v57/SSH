import CLibssh2
import Foundation

/// One login that runs many commands, each on a channel of its own without a terminal: standard output and standard
/// error arrive apart and byte for byte (no `\r\n`), input is written and then closed, and each command ends with
/// its exit status. Commands run side by side over the one session, so a burst of short commands (a git client's
/// refresh) costs one handshake. It logs in like `SFTPClient` (`SSHLogin`: host key check, key or password, optional
/// jump host); one thread owns the session and drives every channel.
public final class SSHConnection: @unchecked Sendable {
  /// What a command printed, and how it ended.
  public struct Output: Sendable {
    public var stdout: Data
    public var stderr: Data
    /// nil when the server sent none (the command ended by a signal, or its channel was closed).
    public var status: Int32?
  }

  public let server: SSHServer
  /// `SHA256:…`, to remember after the first login (as `SSHServer.knownFingerprint` next time).
  public private(set) var hostKeyFingerprint = ""

  private let lock = NSLock()
  private var running = true
  private var closeReason: String?
  private var closedHandlers: [@Sendable (String?) -> Void] = []
  /// Commands waiting for the owner thread to open their channel.
  private var queued: [Exec] = []
  private let waker = PollWaker()

  /// Owner thread only.
  private let login: SSHLogin
  private var execs: [Exec] = []

  private static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  private init(server: SSHServer, jump: SSHJump?) {
    self.server = server
    login = SSHLogin(server: server, jump: jump)
  }

  /// Logs in (through `jump` first if there is one). `timeout` covers the login.
  public static func connect(
    server: SSHServer, through jump: SSHServer? = nil, timeout: TimeInterval = 20
  ) async throws -> SSHConnection {
    var hop: SSHJump?
    if let jump { hop = try await SSHJump.open(to: server, through: jump, timeout: timeout) }
    let connection = SSHConnection(server: server, jump: hop)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      let thread = Thread { connection.run(timeout: timeout, ready: continuation) }
      thread.name = "SSHConnection \(server.host)"
      thread.qualityOfService = .userInitiated
      thread.start()
    }
    return connection
  }

  public var isAlive: Bool { lock.withLock { running } }

  /// Called once, on any thread, when the connection ends (with a reason if it broke).
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

  /// Logs out; commands still running fail with `SSHTunnelError.closed`.
  public func close() {
    stop(reason: nil)
  }

  /// Runs `command` through the login shell (`$SHELL -c`, as `ssh host command` does), writes `input` to it and
  /// closes its input, and returns what it printed once it ends. `onError` gets standard error as it arrives (for
  /// progress lines). Cancelling the task closes the command's channel.
  public func run(
    _ command: String, input: Data? = nil, onError: (@Sendable (Data) -> Void)? = nil
  ) async throws -> Output {
    let exec = Exec(command: command, input: input ?? Data(), onError: onError)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Output, Error>) in
        exec.continuation = continuation
        lock.lock()
        guard running else {
          lock.unlock()
          exec.finish(.failure(SSHTunnelError.closed))
          return
        }
        queued.append(exec)
        lock.unlock()
        waker.wake()
      }
    } onCancel: {
      exec.cancel()
      waker.wake()
    }
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
      // Keepalives without replies, so an idle session has nothing waiting to be read.
      if let session = login.session { libssh2_keepalive_config(session, 0, 30) }
    } catch {
      login.teardown()
      lock.withLock { running = false }
      ready.resume(throwing: error)
      return
    }
    ready.resume()
    loop()
    let waiting = lock.withLock {
      defer { queued = [] }
      return queued
    }
    let reason = lock.withLock { closeReason }
    let error = reason.map { SSHTunnelError.forwardFailed($0) } ?? .closed
    for exec in waiting + execs {
      if let channel = exec.channel { libssh2_channel_free(channel) }
      exec.finish(.failure(error))
    }
    execs = []
    login.teardown()
    waker.close()
  }

  private func loop() {
    var lastKeepalive = Date()
    while true {
      let fresh: [Exec]? = lock.withLock {
        guard running else { return nil }
        defer { queued = [] }
        return queued
      }
      guard let fresh, let session = login.session else { return }
      execs += fresh

      var progressed = false
      for exec in execs { progressed = step(exec, session: session) || progressed }
      execs.removeAll { $0.isFinished }
      if login.isTransportDead {
        stop(reason: "The SSH server closed the connection.")
        return
      }
      if progressed { continue }

      if Date().timeIntervalSince(lastKeepalive) > 15 {
        var next: Int32 = 0
        let rc = libssh2_keepalive_send(session, &next)
        if rc < 0 && rc != Self.eagain {
          stop(reason: "The SSH connection dropped (\(login.lastError())).")
          return
        }
        lastKeepalive = Date()
      }
      wait(session: session)
    }
  }

  /// Sleeps until the socket is ready the way libssh2 last wanted it, a command is queued or cancelled, or a
  /// moment passed.
  private func wait(session: OpaquePointer) {
    let directions = libssh2_session_block_directions(session)
    var events = Sockets.readable
    if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND != 0 { events |= Sockets.writable }
    var descriptors = [Sockets.descriptor(login.socket, events: events)]
    if waker.isValid { descriptors.append(Sockets.descriptor(waker.fd, events: Sockets.readable)) }
    Sockets.poll(&descriptors, milliseconds: execs.isEmpty ? 5000 : 200)
    if waker.isValid { waker.drain() }
  }

  /// Moves one command along as far as it goes without blocking; whether anything happened.
  private func step(_ exec: Exec, session: OpaquePointer) -> Bool {
    if exec.isCancelled, exec.stage != .done {
      if let channel = exec.channel {
        _ = libssh2_channel_close(channel)
        libssh2_channel_free(channel)
        exec.channel = nil
      }
      exec.finish(.failure(CancellationError()))
      return true
    }
    var progressed = false
    do {
      if exec.stage == .opening {
        guard
          let channel = libssh2_channel_open_ex(session, "session", 7, UInt32(2 * 1024 * 1024), UInt32(32 * 1024), nil, 0)
        else {
          guard libssh2_session_last_errno(session) == Self.eagain else {
            throw SSHTunnelError.forwardFailed("the server didn't open a session (\(login.lastError()))")
          }
          return false
        }
        exec.channel = channel
        exec.stage = .starting
        progressed = true
      }
      guard let channel = exec.channel else { return progressed }
      if exec.stage == .starting {
        let command = exec.command
        let rc = libssh2_channel_process_startup(channel, "exec", 4, command, UInt32(command.utf8.count))
        if rc == Self.eagain { return progressed }
        guard rc == 0 else { throw SSHTunnelError.forwardFailed("the server refused the command (\(login.lastError()))") }
        exec.stage = .writing
        progressed = true
      }
      if exec.stage == .writing {
        while exec.written < exec.input.count {
          let count = exec.input.withUnsafeBytes { bytes in
            libssh2_channel_write_ex(
              channel, 0, bytes.baseAddress!.assumingMemoryBound(to: CChar.self) + exec.written,
              min(exec.input.count - exec.written, 32 * 1024))
          }
          if count == Int(Self.eagain) { break }
          // The command may end without reading all of it: what's left is dropped, as a broken pipe would.
          if count < 0 {
            exec.written = exec.input.count
            break
          }
          exec.written += count
          progressed = true
        }
        if exec.written >= exec.input.count {
          let rc = libssh2_channel_send_eof(channel)
          if rc != Self.eagain {
            exec.stage = .reading
            progressed = true
          }
        }
      }
      // Output is read while input is still going out, so neither side's window fills up and stalls the other.
      if exec.stage == .writing || exec.stage == .reading {
        progressed = try read(exec, channel: channel) || progressed
        if exec.stage == .reading, libssh2_channel_eof(channel) != 0 {
          exec.stage = .closing
          progressed = true
        }
      }
      if exec.stage == .closing {
        let rc = libssh2_channel_close(channel)
        if rc == Self.eagain { return progressed }
        let waited = libssh2_channel_wait_closed(channel)
        if waited == Self.eagain { return progressed }
        var signal: UnsafeMutablePointer<CChar>?
        var length = 0
        _ = libssh2_channel_get_exit_signal(channel, &signal, &length, nil, nil, nil, nil)
        let status: Int32?
        if let signal {
          free(signal)
          status = nil
        } else {
          status = libssh2_channel_get_exit_status(channel)
        }
        libssh2_channel_free(channel)
        exec.channel = nil
        exec.finish(.success(Output(stdout: exec.stdout, stderr: exec.stderr, status: status)))
        return true
      }
    } catch {
      if let channel = exec.channel {
        libssh2_channel_free(channel)
        exec.channel = nil
      }
      exec.finish(.failure(error))
      return true
    }
    return progressed
  }

  private func read(_ exec: Exec, channel: OpaquePointer) throws -> Bool {
    var progressed = false
    var buffer = [CChar](repeating: 0, count: 32 * 1024)
    for stream: Int32 in [0, SSH_EXTENDED_DATA_STDERR] {
      while true {
        let count = libssh2_channel_read_ex(channel, stream, &buffer, buffer.count)
        if count > 0 {
          let data = Data(bytes: buffer, count: count)
          if stream == 0 {
            exec.stdout.append(data)
          } else {
            exec.stderr.append(data)
            exec.onError?(data)
          }
          progressed = true
          continue
        }
        if count < 0 && Int32(count) != Self.eagain {
          throw SSHTunnelError.forwardFailed("the command's output broke off (\(login.lastError()))")
        }
        break
      }
    }
    return progressed
  }

  /// One command and its channel. The owner thread changes everything but `cancelled`.
  private final class Exec: @unchecked Sendable {
    enum Stage { case opening, starting, writing, reading, closing, done }

    let command: String
    let input: Data
    let onError: (@Sendable (Data) -> Void)?
    var continuation: CheckedContinuation<Output, Error>?
    var stage = Stage.opening
    var channel: OpaquePointer?
    var written = 0
    var stdout = Data()
    var stderr = Data()

    private let lock = NSLock()
    private var cancelled = false

    init(command: String, input: Data, onError: (@Sendable (Data) -> Void)?) {
      self.command = command
      self.input = input
      self.onError = onError
    }

    var isCancelled: Bool { lock.withLock { cancelled } }
    var isFinished: Bool { stage == .done }

    func cancel() { lock.withLock { cancelled = true } }

    func finish(_ result: Result<Output, Error>) {
      stage = .done
      let continuation = lock.withLock {
        defer { self.continuation = nil }
        return self.continuation
      }
      continuation?.resume(with: result)
    }
  }
}
