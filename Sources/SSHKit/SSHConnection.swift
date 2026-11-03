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
  /// The address that answered: `server.host`, or one of `server.fallbackHosts`.
  public private(set) var connectedHost = ""

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

  /// Starts `command` like `run`, keeping its input open and handing its output over as it arrives, for a program that
  /// talks back and forth (`git-receive-pack`). A failure to start shows up in the channel's `read`.
  public func open(_ command: String) -> Channel {
    let exec = Exec(command: command, input: Data(), onError: nil, isChannel: true)
    let isRunning = lock.withLock {
      if running { queued.append(exec) }
      return running
    }
    if !isRunning { exec.finish(.failure(SSHTunnelError.closed)) }
    waker.wake()
    return Channel(exec: exec, waker: waker, connection: self)
  }

  /// A command started with `open`: its standard output as it arrives, what it should read, and how it ended.
  public final class Channel: @unchecked Sendable {
    private let exec: Exec
    private let waker: PollWaker
    /// Keeps the connection, whose thread drives the channel, while the channel is in use.
    private let connection: SSHConnection

    fileprivate init(exec: Exec, waker: PollWaker, connection: SSHConnection) {
      self.exec = exec
      self.waker = waker
      self.connection = connection
    }

    /// Queues `data` for the command's input.
    public func write(_ data: Data) {
      exec.queue(data)
      waker.wake()
    }

    /// Closes the command's input once what's queued has gone out.
    public func finishWriting() {
      exec.finishInput()
      waker.wake()
    }

    /// The next piece of standard output, nil once there's no more. Throws when the channel broke or the task was
    /// cancelled; a command that failed ends normally here (`finished` has its status).
    public func read() async throws -> Data? {
      try await withTaskCancellationHandler {
        let data = try await exec.nextOutput()
        waker.wake()
        return data
      } onCancel: {
        exec.cancel()
        waker.wake()
      }
    }

    /// The command's standard error and exit status, once it ended (`stdout` is empty: `read` had it).
    public func finished() async throws -> Output {
      try await exec.outcome()
    }

    /// Closes the channel; the command gets a hang-up if it's still running.
    public func close() {
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
      connectedHost = login.connectedHost
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
    // Nothing may be read while every reader is behind, so data on the socket can't be what to wake for.
    if !execs.isEmpty, execs.allSatisfy(\.isOutputFull), waker.isValid { descriptors = [] }
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
        exec.collectInput()
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
        if exec.written >= exec.input.count, exec.isInputFinished {
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
        // A channel's input may stay open for as long as its command runs, so its end can come at any stage.
        if exec.stage == .reading || exec.isChannel, !exec.isOutputFull, libssh2_channel_eof(channel) != 0 {
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
      // The server's window fills up while a channel's reader is behind, which holds the command back.
      while stream != 0 || !exec.isOutputFull {
        let count = libssh2_channel_read_ex(channel, stream, &buffer, buffer.count)
        if count > 0 {
          let data = Data(bytes: buffer, count: count)
          if stream == 0 {
            if exec.isChannel { exec.deliver(data) } else { exec.stdout.append(data) }
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

  /// One command and its channel. The owner thread changes everything but what `lock` guards.
  fileprivate final class Exec: @unchecked Sendable {
    enum Stage { case opening, starting, writing, reading, closing, done }

    /// How much output waits for a channel's reader before reading stops.
    private static let outputLimit = 4 * 1024 * 1024

    let command: String
    let onError: (@Sendable (Data) -> Void)?
    /// Output and input go through `read` and `write` (`SSHConnection.open`), not `run`.
    let isChannel: Bool
    var continuation: CheckedContinuation<Output, Error>?
    var stage = Stage.opening
    var channel: OpaquePointer?
    var input = Data()
    var written = 0
    var stdout = Data()
    var stderr = Data()

    private let lock = NSLock()
    private var cancelled = false
    private var queuedInput: Data
    private var inputFinished: Bool
    private var output: [Data] = []
    private var outputSize = 0
    private var reader: CheckedContinuation<Data?, Error>?
    private var result: Result<Output, Error>?
    private var waiters: [CheckedContinuation<Output, Error>] = []

    init(command: String, input: Data, onError: (@Sendable (Data) -> Void)?, isChannel: Bool = false) {
      self.command = command
      queuedInput = input
      inputFinished = !isChannel
      self.onError = onError
      self.isChannel = isChannel
    }

    var isCancelled: Bool { lock.withLock { cancelled } }
    var isFinished: Bool { stage == .done }
    var isInputFinished: Bool { lock.withLock { inputFinished } }
    var isOutputFull: Bool { lock.withLock { outputSize >= Self.outputLimit } }

    func cancel() { lock.withLock { cancelled = true } }

    func queue(_ data: Data) { lock.withLock { queuedInput.append(data) } }

    func finishInput() { lock.withLock { inputFinished = true } }

    /// Owner thread: moves queued input to where it's written from.
    func collectInput() {
      let queued = lock.withLock {
        defer { queuedInput = Data() }
        return queuedInput
      }
      guard !queued.isEmpty else { return }
      if written >= input.count {
        input = queued
        written = 0
      } else {
        input.append(queued)
      }
    }

    /// Owner thread: hands output to the reader, or keeps it for the next read.
    func deliver(_ data: Data) {
      let waiting = lock.withLock { () -> CheckedContinuation<Data?, Error>? in
        if let reader {
          self.reader = nil
          return reader
        }
        output.append(data)
        outputSize += data.count
        return nil
      }
      waiting?.resume(returning: data)
    }

    func nextOutput() async throws -> Data? {
      try await withCheckedThrowingContinuation { continuation in
        lock.lock()
        if !output.isEmpty {
          let data = output.removeFirst()
          outputSize -= data.count
          lock.unlock()
          continuation.resume(returning: data)
        } else if let result {
          lock.unlock()
          switch result {
          case .success: continuation.resume(returning: nil)
          case .failure(let error): continuation.resume(throwing: error)
          }
        } else {
          reader = continuation
          lock.unlock()
        }
      }
    }

    func outcome() async throws -> Output {
      try await withCheckedThrowingContinuation { continuation in
        lock.lock()
        if let result {
          lock.unlock()
          continuation.resume(with: result)
        } else {
          waiters.append(continuation)
          lock.unlock()
        }
      }
    }

    func finish(_ result: Result<Output, Error>) {
      stage = .done
      let (continuation, reader, waiters) = lock.withLock {
        defer {
          self.continuation = nil
          self.reader = nil
          self.waiters = []
          self.result = result
        }
        return (self.continuation, self.reader, self.waiters)
      }
      continuation?.resume(with: result)
      switch result {
      case .success: reader?.resume(returning: nil)
      case .failure(let error): reader?.resume(throwing: error)
      }
      for waiter in waiters { waiter.resume(with: result) }
    }
  }
}
