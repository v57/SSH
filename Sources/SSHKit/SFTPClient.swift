import CLibssh2
import Foundation

/// A file or folder on an SFTP server.
public struct SFTPFileInfo: Sendable, Hashable {
  public enum Kind: String, Sendable, Hashable {
    case file
    case directory
    case symbolicLink
    case other
  }

  /// The path as asked for (a listed entry's is the folder's path joined with its name).
  public var path: String
  /// What it is; for a symbolic link that was followed, what it points to.
  public var kind: Kind
  /// The entry itself is a symbolic link (known from `list`, and from `stat` with `followLinks: false`).
  public var isSymbolicLink: Bool
  public var size: UInt64
  public var modified: Date?
  /// The permission bits (`0o7777`); nil when the server didn't send them.
  public var permissions: UInt32?

  public init(
    path: String, kind: Kind, isSymbolicLink: Bool = false, size: UInt64 = 0, modified: Date? = nil,
    permissions: UInt32? = nil
  ) {
    self.path = path
    self.kind = kind
    self.isSymbolicLink = isSymbolicLink
    self.size = size
    self.modified = modified
    self.permissions = permissions
  }

  public var name: String { path.split(separator: "/").last.map(String.init) ?? path }
  public var isDirectory: Bool { kind == .directory }
}

public enum SFTPError: Error, LocalizedError, Sendable, Equatable {
  case noSuchFile(String)
  case permissionDenied(String)
  case alreadyExists(String)
  case directoryNotEmpty(String)
  case notADirectory(String)
  case isADirectory(String)
  /// The server doesn't do this (an SFTP extension it lacks).
  case unsupported(String)
  /// Any other refusal: the SFTP status code (`LIBSSH2_FX_*`) and what libssh2 said.
  case failed(path: String, status: UInt, message: String)
  /// The SSH connection broke or timed out; the client is closed.
  case connectionLost(String)
  case closed

  /// The server said no (as opposed to the connection failing).
  var isRefusal: Bool {
    switch self {
    case .connectionLost, .closed: false
    default: true
    }
  }

  public var errorDescription: String? {
    switch self {
    case .noSuchFile(let path): "“\(path)” doesn’t exist on the server."
    case .permissionDenied(let path): "The server doesn’t allow access to “\(path)”."
    case .alreadyExists(let path): "“\(path)” already exists on the server."
    case .directoryNotEmpty(let path): "The folder “\(path)” isn’t empty."
    case .notADirectory(let path): "“\(path)” isn’t a folder."
    case .isADirectory(let path): "“\(path)” is a folder."
    case .unsupported(let what): "The SFTP server doesn’t support \(what)."
    case .failed(let path, let status, let message):
      "The SFTP server refused “\(path)” (status \(status)\(message.isEmpty ? "" : ": \(message)"))."
    case .connectionLost(let detail): "The SFTP connection broke: \(detail)"
    case .closed: "The SFTP connection is closed."
    }
  }
}

/// Files on an SSH server over SFTP, logged in the way `SSHTunnel` logs in (same host key check, key or password,
/// optional jump host).
///
/// Paths are the server's: absolute, or relative to the login folder (`realPath(".")` gives it). Every call is
/// async and may come from any thread; one thread owns the libssh2 session and runs the calls one at a time.
public final class SFTPClient: @unchecked Sendable {
  public let server: SSHServer
  /// `SHA256:…`, to remember after the first login (as `SSHServer.knownFingerprint` next time).
  public private(set) var hostKeyFingerprint = ""
  public private(set) var hostKeyType = ""
  /// The jump host's key, when the login went through one.
  public let jumpHostKeyFingerprint: String?

  private let lock = NSLock()
  private var running = true
  private var closeReason: String?
  private var closedHandlers: [@Sendable (String?) -> Void] = []
  private var jobs: [Job] = []
  private let waker = PollWaker()
  private let operationTimeout: TimeInterval

  /// Owner thread only.
  private let login: SSHLogin
  private var sftp: OpaquePointer?

  private static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)
  private static let chunk = 256 * 1024

  private init(server: SSHServer, jump: SSHJump?, operationTimeout: TimeInterval) {
    self.server = server
    login = SSHLogin(server: server, jump: jump)
    jumpHostKeyFingerprint = jump?.hostKeyFingerprint
    self.operationTimeout = operationTimeout
  }

  /// Logs in (through `jump` first if there is one) and starts SFTP. `timeout` covers the login,
  /// `operationTimeout` how long one call may wait for the server without progress.
  public static func connect(
    server: SSHServer, through jump: SSHServer? = nil, timeout: TimeInterval = 20, operationTimeout: TimeInterval = 60
  ) async throws -> SFTPClient {
    var hop: SSHJump?
    if let jump { hop = try await SSHJump.open(to: server, through: jump, timeout: timeout) }
    let client = SFTPClient(server: server, jump: hop, operationTimeout: operationTimeout)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      let thread = Thread { client.run(timeout: timeout, ready: continuation) }
      thread.name = "SFTPClient \(server.host)"
      thread.qualityOfService = .userInitiated
      thread.start()
    }
    return client
  }

  public var isAlive: Bool {
    lock.lock()
    defer { lock.unlock() }
    return running
  }

  /// Called once, on any thread, when the client stops (with a reason if the connection broke).
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

  /// Logs out; calls still waiting fail with `SFTPError.closed`.
  public func close() {
    stop(reason: nil)
  }

  // MARK: - Files

  /// The absolute, canonical form of `path` ("." is the login folder).
  public func realPath(_ path: String) async throws -> String {
    try await perform { try $0.realPathNow(path) }
  }

  /// The entries of a folder, without "." and "..", sorted by name. Symbolic links are followed when
  /// `followLinks` (a broken one stays a `.symbolicLink`).
  public func list(_ path: String, followLinks: Bool = true) async throws -> [SFTPFileInfo] {
    try await perform { try $0.listNow(path, followLinks: followLinks) }
  }

  /// nil when nothing is at `path`.
  public func stat(_ path: String, followLinks: Bool = true) async throws -> SFTPFileInfo? {
    try await perform { try $0.statNow(path, followLinks: followLinks) }
  }

  /// `length` bytes from `offset` (to the end when nil); fewer when the file ends first, none past its end.
  public func read(_ path: String, offset: UInt64 = 0, length: Int? = nil) async throws -> Data {
    try await perform { try $0.readNow(path, offset: offset, length: length) }
  }

  /// Creates or replaces the file. `atomic` writes a temporary file next to it and renames it over the old one,
  /// so readers see the old or the new file, never half of one (falling back to writing in place where the folder
  /// can't take a new file); a replaced file keeps its permissions. `createParents` makes missing folders first.
  public func write(
    _ data: Data, to path: String, atomic: Bool = true, createParents: Bool = false, permissions: UInt32 = 0o644
  ) async throws {
    try await perform {
      try $0.writeNow(data, to: path, atomic: atomic, createParents: createParents, permissions: permissions)
    }
  }

  /// Makes a folder; with `intermediate`, its missing parents too and no error if it's already there (`mkdir -p`).
  public func createDirectory(_ path: String, intermediate: Bool = true, permissions: UInt32 = 0o755) async throws {
    try await perform { try $0.createDirectoryNow(path, intermediate: intermediate, permissions: permissions) }
  }

  /// Moves a file or folder. `replacing` replaces a file at the destination (atomically, with OpenSSH's
  /// posix-rename); a folder is never replaced.
  public func rename(_ source: String, to destination: String, replacing: Bool = true) async throws {
    try await perform { try $0.renameNow(source, to: destination, replacing: replacing) }
  }

  public func removeFile(_ path: String) async throws {
    try await perform { try $0.removeFileNow(path) }
  }

  /// Removes an empty folder.
  public func removeDirectory(_ path: String) async throws {
    try await perform { try $0.removeDirectoryNow(path) }
  }

  // MARK: - Jobs

  private struct Job: @unchecked Sendable {
    let run: (SFTPClient) -> Void
    let fail: (Error) -> Void
  }

  private func perform<T: Sendable>(_ body: @escaping @Sendable (SFTPClient) throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
      let job = Job(
        run: { client in
          do { continuation.resume(returning: try body(client)) } catch { continuation.resume(throwing: error) }
        },
        fail: { continuation.resume(throwing: $0) })
      lock.lock()
      guard running else {
        lock.unlock()
        continuation.resume(throwing: SFTPError.closed)
        return
      }
      jobs.append(job)
      lock.unlock()
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
      hostKeyType = login.hostKeyType
      try startSFTP(deadline: Date().addingTimeInterval(timeout))
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
    lock.lock()
    let waiting = jobs
    jobs = []
    lock.unlock()
    for job in waiting { job.fail(SFTPError.closed) }
    teardown()
  }

  private func startSFTP(deadline: Date) throws {
    guard let session = login.session else { throw SSHTunnelError.closed }
    // Keepalives without replies, so an idle session has nothing waiting to be read.
    libssh2_keepalive_config(session, 0, 30)
    while true {
      if let handle = libssh2_sftp_init(session) {
        sftp = handle
        return
      }
      guard libssh2_session_last_errno(session) == Self.eagain, Date() < deadline else {
        throw SSHTunnelError.handshakeFailed("the server didn't start SFTP (\(login.lastError()))")
      }
      login.waitSocket()
    }
  }

  private func loop() {
    var lastKeepalive = Date()
    while true {
      lock.lock()
      if !running {
        lock.unlock()
        return
      }
      let job = jobs.isEmpty ? nil : jobs.removeFirst()
      lock.unlock()
      if let job {
        job.run(self)
        if login.isTransportDead { stop(reason: "The SSH server closed the connection.") }
        continue
      }
      if Date().timeIntervalSince(lastKeepalive) > 15, let session = login.session {
        var next: Int32 = 0
        let rc = libssh2_keepalive_send(session, &next)
        if rc < 0 && rc != Self.eagain {
          stop(reason: "The SSH connection dropped (\(login.lastError())).")
          return
        }
        lastKeepalive = Date()
      }
      if waker.isValid {
        var fds = [Sockets.descriptor(waker.fd, events: Sockets.readable)]
        Sockets.poll(&fds, milliseconds: 5000)
        waker.drain()
      } else {
        Thread.sleep(forTimeInterval: 0.05)
      }
    }
  }

  private func teardown() {
    if let sftp {
      var rc: Int32
      let deadline = Date().addingTimeInterval(2)
      repeat {
        rc = libssh2_sftp_shutdown(sftp)
        if rc == Self.eagain { login.waitSocket() }
      } while rc == Self.eagain && Date() < deadline
      self.sftp = nil
    }
    login.teardown(reason: "Closing SFTP")
    waker.close()
  }

  // MARK: libssh2 calls (owner thread)

  /// Repeats a call while libssh2 would block, until it returns ≥ 0 (returned) or fails.
  private func call(_ path: String, _ op: () -> Int) throws -> Int {
    var deadline = Date().addingTimeInterval(operationTimeout)
    while true {
      let rc = op()
      if rc >= 0 { return rc }
      guard rc == Self.eagain else { throw failure(Int32(rc), path: path) }
      try waitForServer(&deadline)
    }
  }

  /// Repeats a call that returns a handle while libssh2 would block.
  private func handle(_ path: String, _ op: () -> OpaquePointer?) throws -> OpaquePointer {
    var deadline = Date().addingTimeInterval(operationTimeout)
    while true {
      if let handle = op() { return handle }
      let rc = login.session.map { libssh2_session_last_errno($0) } ?? Int32(LIBSSH2_ERROR_SOCKET_DISCONNECT)
      guard rc == Self.eagain else { throw failure(rc, path: path) }
      try waitForServer(&deadline)
    }
  }

  private func waitForServer(_ deadline: inout Date) throws {
    guard isAlive else { throw SFTPError.closed }
    guard Date() < deadline else {
      stop(reason: "The SFTP server stopped answering.")
      throw SFTPError.connectionLost("the server stopped answering")
    }
    login.waitSocket()
  }

  private func failure(_ rc: Int32, path: String) -> SFTPError {
    if rc == LIBSSH2_ERROR_SFTP_PROTOCOL, let sftp {
      let status = libssh2_sftp_last_error(sftp)
      switch status {
      case LIBSSH2_FX_NO_SUCH_FILE, LIBSSH2_FX_NO_SUCH_PATH: return .noSuchFile(path)
      case LIBSSH2_FX_PERMISSION_DENIED, LIBSSH2_FX_WRITE_PROTECT: return .permissionDenied(path)
      case LIBSSH2_FX_FILE_ALREADY_EXISTS: return .alreadyExists(path)
      case LIBSSH2_FX_DIR_NOT_EMPTY: return .directoryNotEmpty(path)
      case LIBSSH2_FX_NOT_A_DIRECTORY: return .notADirectory(path)
      case LIBSSH2_FX_OP_UNSUPPORTED: return .unsupported("this operation")
      case 24: return .isADirectory(path)  // SSH_FX_FILE_IS_A_DIRECTORY (SFTP v6)
      default: return .failed(path: path, status: UInt(status), message: login.lastError())
      }
    }
    let detail = rc == LIBSSH2_ERROR_TIMEOUT ? "timed out" : login.lastError()
    stop(reason: "The SFTP connection broke (\(detail)).")
    return .connectionLost(detail)
  }

  private func closeHandle(_ handle: OpaquePointer, path: String) throws {
    _ = try call(path) { Int(libssh2_sftp_close_handle(handle)) }
  }

  private var session: OpaquePointer {
    get throws {
      guard let sftp else { throw SFTPError.closed }
      return sftp
    }
  }

  // MARK: Operations (owner thread)

  fileprivate func realPathNow(_ path: String) throws -> String {
    let sftp = try session
    var buffer = [CChar](repeating: 0, count: 4096)
    let length = try call(path) {
      Int(
        libssh2_sftp_symlink_ex(
          sftp, path, UInt32(path.utf8.count), &buffer, UInt32(buffer.count), LIBSSH2_SFTP_REALPATH))
    }
    return String(decoding: buffer[0..<length].map { UInt8(bitPattern: $0) }, as: UTF8.self)
  }

  fileprivate func statNow(_ path: String, followLinks: Bool) throws -> SFTPFileInfo? {
    let sftp = try session
    var attributes = LIBSSH2_SFTP_ATTRIBUTES()
    do {
      _ = try call(path) {
        Int(
          libssh2_sftp_stat_ex(
            sftp, path, UInt32(path.utf8.count), followLinks ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT, &attributes))
      }
    } catch SFTPError.noSuchFile {
      return nil
    }
    var info = Self.info(path: path, attributes)
    // Followed, the server says what the link points to, not that it is one.
    if followLinks { info.isSymbolicLink = false }
    return info
  }

  fileprivate func listNow(_ path: String, followLinks: Bool) throws -> [SFTPFileInfo] {
    let sftp = try session
    let directory: OpaquePointer
    do {
      directory = try handle(path) {
        libssh2_sftp_open_ex(sftp, path, UInt32(path.utf8.count), 0, 0, LIBSSH2_SFTP_OPENDIR)
      }
    } catch let error as SFTPError {
      guard error.isRefusal else { throw error }
      // OpenSSH says "no such file" or "failure" for a file.
      if let info = try statNow(path, followLinks: true), !info.isDirectory { throw SFTPError.notADirectory(path) }
      throw error
    }
    var entries: [SFTPFileInfo] = []
    var name = [CChar](repeating: 0, count: 4096)
    do {
      while true {
        var attributes = LIBSSH2_SFTP_ATTRIBUTES()
        let length = try call(path) {
          Int(libssh2_sftp_readdir_ex(directory, &name, name.count, nil, 0, &attributes))
        }
        if length == 0 { break }
        let entry = String(decoding: name[0..<length].map { UInt8(bitPattern: $0) }, as: UTF8.self)
        if entry == "." || entry == ".." { continue }
        var info = Self.info(path: Self.join(path, entry), attributes)
        if followLinks, info.kind == .symbolicLink, let target = try statNow(info.path, followLinks: true) {
          info = SFTPFileInfo(
            path: info.path, kind: target.kind, isSymbolicLink: true, size: target.size, modified: target.modified,
            permissions: target.permissions)
        }
        entries.append(info)
      }
    } catch {
      try? closeHandle(directory, path: path)
      throw error
    }
    try closeHandle(directory, path: path)
    return entries.sorted { $0.name < $1.name }
  }

  fileprivate func readNow(_ path: String, offset: UInt64, length: Int?) throws -> Data {
    let sftp = try session
    let file = try handle(path) {
      libssh2_sftp_open_ex(sftp, path, UInt32(path.utf8.count), UInt(LIBSSH2_FXF_READ), 0, LIBSSH2_SFTP_OPENFILE)
    }
    var result = Data()
    do {
      var attributes = LIBSSH2_SFTP_ATTRIBUTES()
      _ = try call(path) { Int(libssh2_sftp_fstat_ex(file, &attributes, 0)) }
      let info = Self.info(path: path, attributes)
      if info.isDirectory { throw SFTPError.isADirectory(path) }
      let available = info.size > offset ? Int(clamping: info.size - offset) : 0
      var remaining = length ?? Int.max
      if remaining > 0, attributes.flags & UInt(LIBSSH2_SFTP_ATTR_SIZE) != 0 {
        result.reserveCapacity(min(remaining, available))
      }
      libssh2_sftp_seek64(file, offset)
      var buffer = [CChar](repeating: 0, count: Self.chunk)
      while remaining > 0 {
        let wanted = min(remaining, buffer.count)
        let n = try call(path) { libssh2_sftp_read(file, &buffer, wanted) }
        if n == 0 { break }
        buffer.withUnsafeBytes { result.append($0.bindMemory(to: UInt8.self).baseAddress!, count: n) }
        remaining -= n
      }
    } catch {
      try? closeHandle(file, path: path)
      throw error
    }
    try closeHandle(file, path: path)
    return result
  }

  fileprivate func writeNow(
    _ data: Data, to path: String, atomic: Bool, createParents: Bool, permissions: UInt32
  ) throws {
    let parent = Self.parent(path)
    if createParents, !parent.isEmpty, parent != "/" {
      try createDirectoryNow(parent, intermediate: true, permissions: 0o755)
    }
    let entry = try statNow(path, followLinks: false)
    let existing = entry?.kind == .symbolicLink ? try statNow(path, followLinks: true) : entry
    if existing?.isDirectory == true { throw SFTPError.isADirectory(path) }
    let mode = existing?.permissions ?? permissions
    // A symbolic link is written through, in place: renaming over it would replace the link.
    guard atomic, entry?.kind != .symbolicLink else {
      try writeFile(data, to: path, permissions: mode)
      return
    }
    let temporary = Self.join(parent, ".\(Self.name(path)).\(UUID().uuidString.prefix(8)).part")
    do {
      try writeFile(data, to: temporary, permissions: mode)
    } catch SFTPError.permissionDenied {
      // The folder takes no new files, but the file may be writable.
      try writeFile(data, to: path, permissions: mode)
      return
    }
    do {
      try renameNow(temporary, to: path, replacing: true)
    } catch {
      try? removeFileNow(temporary)
      throw error
    }
  }

  private func writeFile(_ data: Data, to path: String, permissions: UInt32) throws {
    let sftp = try session
    let flags = UInt(LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC)
    let file: OpaquePointer
    do {
      file = try handle(path) {
        libssh2_sftp_open_ex(sftp, path, UInt32(path.utf8.count), flags, Int(permissions), LIBSSH2_SFTP_OPENFILE)
      }
    } catch let error as SFTPError {
      guard error.isRefusal else { throw error }
      if try statNow(path, followLinks: true)?.isDirectory == true { throw SFTPError.isADirectory(path) }
      let parent = Self.parent(path)
      if !parent.isEmpty, parent != "/" {
        if let folder = try statNow(parent, followLinks: true), !folder.isDirectory {
          throw SFTPError.notADirectory(parent)
        }
        // The folder above may be a file.
        let above = Self.parent(parent)
        if !above.isEmpty, above != "/", let folder = try statNow(above, followLinks: true), !folder.isDirectory {
          throw SFTPError.notADirectory(above)
        }
      }
      throw error
    }
    do {
      try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
        var offset = 0
        while offset < bytes.count {
          let count = min(Self.chunk, bytes.count - offset)
          let pointer = bytes.baseAddress!.advanced(by: offset).assumingMemoryBound(to: CChar.self)
          offset += try call(path) { libssh2_sftp_write(file, pointer, count) }
        }
      }
    } catch {
      try? closeHandle(file, path: path)
      throw error
    }
    // Closing reports a failed flush (a full disk).
    try closeHandle(file, path: path)
  }

  fileprivate func createDirectoryNow(_ path: String, intermediate: Bool, permissions: UInt32) throws {
    guard intermediate else {
      try makeDirectory(path, permissions: permissions)
      return
    }
    var current = path.hasPrefix("/") ? "/" : ""
    for part in path.split(separator: "/") where part != "." {
      current = Self.join(current, String(part))
      if let info = try statNow(current, followLinks: true) {
        guard info.isDirectory else { throw SFTPError.notADirectory(current) }
        continue
      }
      do {
        try makeDirectory(current, permissions: permissions)
      } catch SFTPError.alreadyExists {
        // Made by someone else meanwhile.
        guard try statNow(current, followLinks: true)?.isDirectory == true else {
          throw SFTPError.notADirectory(current)
        }
      }
    }
  }

  private func makeDirectory(_ path: String, permissions: UInt32) throws {
    let sftp = try session
    do {
      _ = try call(path) { Int(libssh2_sftp_mkdir_ex(sftp, path, UInt32(path.utf8.count), Int(permissions))) }
    } catch let error as SFTPError {
      guard error.isRefusal else { throw error }
      // OpenSSH says only "failure" when something is already there.
      if try statNow(path, followLinks: false) != nil { throw SFTPError.alreadyExists(path) }
      let parent = Self.parent(path)
      if !parent.isEmpty, parent != "/" {
        guard let folder = try statNow(parent, followLinks: true) else { throw SFTPError.noSuchFile(parent) }
        if !folder.isDirectory { throw SFTPError.notADirectory(parent) }
      }
      throw error
    }
  }

  fileprivate func renameNow(_ source: String, to destination: String, replacing: Bool) throws {
    let sftp = try session
    // Flags reach only SFTP v5+ servers; OpenSSH (v3) never replaces with a plain rename.
    let flags =
      replacing ? Int(LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE) : 0
    func plainRename() throws {
      _ = try call(source) {
        Int(
          libssh2_sftp_rename_ex(
            sftp, source, UInt32(source.utf8.count), destination, UInt32(destination.utf8.count), flags))
      }
    }
    do {
      if replacing {
        do {
          _ = try call(source) {
            Int(
              libssh2_sftp_posix_rename_ex(sftp, source, source.utf8.count, destination, destination.utf8.count))
          }
        } catch SFTPError.unsupported {
          // No posix-rename: a plain rename, after moving a file at the destination out of the way.
          do {
            try plainRename()
          } catch let error as SFTPError {
            guard error.isRefusal, let target = try statNow(destination, followLinks: false),
              !target.isDirectory, try statNow(source, followLinks: false)?.isDirectory == false
            else { throw error }
            try removeFileNow(destination)
            try plainRename()
          }
        }
      } else {
        try plainRename()
      }
    } catch let error as SFTPError {
      switch error {
      case .failed, .noSuchFile, .permissionDenied, .notADirectory, .isADirectory:
        // Say which side was wrong.
        guard try statNow(source, followLinks: false) != nil else { throw SFTPError.noSuchFile(source) }
        if try statNow(destination, followLinks: false) != nil { throw SFTPError.alreadyExists(destination) }
        let parent = Self.parent(destination)
        if !parent.isEmpty, parent != "/", try statNow(parent, followLinks: true)?.isDirectory != true {
          throw SFTPError.noSuchFile(parent)
        }
        throw error
      default:
        throw error
      }
    }
  }

  fileprivate func removeFileNow(_ path: String) throws {
    let sftp = try session
    do {
      _ = try call(path) { Int(libssh2_sftp_unlink_ex(sftp, path, UInt32(path.utf8.count))) }
    } catch let error as SFTPError {
      guard error.isRefusal else { throw error }
      if try statNow(path, followLinks: false)?.isDirectory == true { throw SFTPError.isADirectory(path) }
      throw error
    }
  }

  fileprivate func removeDirectoryNow(_ path: String) throws {
    let sftp = try session
    do {
      _ = try call(path) { Int(libssh2_sftp_rmdir_ex(sftp, path, UInt32(path.utf8.count))) }
    } catch let error as SFTPError {
      switch error {
      case .directoryNotEmpty, .notADirectory, .connectionLost, .closed: throw error
      default:
        // OpenSSH says "no such file" for a file, "failure" for a full folder.
        guard let info = try statNow(path, followLinks: false) else { throw SFTPError.noSuchFile(path) }
        guard info.isDirectory else { throw SFTPError.notADirectory(path) }
        if try !listNow(path, followLinks: false).isEmpty { throw SFTPError.directoryNotEmpty(path) }
        throw error
      }
    }
  }

  // MARK: Helpers

  static func info(path: String, _ attributes: LIBSSH2_SFTP_ATTRIBUTES) -> SFTPFileInfo {
    var kind = SFTPFileInfo.Kind.other
    var permissions: UInt32?
    if attributes.flags & UInt(LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0 {
      let mode = UInt32(truncatingIfNeeded: attributes.permissions)
      permissions = mode & 0o7777
      switch mode & 0o170000 {
      case 0o040000: kind = .directory
      case 0o100000: kind = .file
      case 0o120000: kind = .symbolicLink
      default: kind = .other
      }
    }
    let size = attributes.flags & UInt(LIBSSH2_SFTP_ATTR_SIZE) != 0 ? UInt64(attributes.filesize) : 0
    let modified =
      attributes.flags & UInt(LIBSSH2_SFTP_ATTR_ACMODTIME) != 0
      ? Date(timeIntervalSince1970: TimeInterval(attributes.mtime)) : nil
    return SFTPFileInfo(
      path: path, kind: kind, isSymbolicLink: kind == .symbolicLink, size: kind == .directory ? 0 : size,
      modified: modified, permissions: permissions)
  }

  static func join(_ folder: String, _ name: String) -> String {
    if folder.isEmpty { return name }
    return folder.hasSuffix("/") ? folder + name : folder + "/" + name
  }

  /// The folder holding `path` ("" for a bare name, "/" for a top-level absolute path).
  static func parent(_ path: String) -> String {
    var trimmed = Substring(path)
    while trimmed.count > 1, trimmed.hasSuffix("/") { trimmed = trimmed.dropLast() }
    guard let slash = trimmed.lastIndex(of: "/") else { return "" }
    return slash == trimmed.startIndex ? "/" : String(trimmed[..<slash])
  }

  static func name(_ path: String) -> String {
    path.split(separator: "/").last.map(String.init) ?? path
  }
}
