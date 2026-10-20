import Foundation

#if os(Windows)
  import WinSDK
#elseif canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

#if os(Windows)
  /// A socket: libssh2's `libssh2_socket_t`.
  public typealias SocketHandle = SOCKET
  public typealias PollDescriptor = WSAPOLLFD
#else
  public typealias SocketHandle = Int32
  public typealias PollDescriptor = pollfd
#endif

/// Why a socket couldn't connect or listen.
public enum SocketError: Error, Sendable, Equatable {
  /// The host name didn't resolve.
  case hostNotFound(String)
  /// Nothing answered within the timeout.
  case timedOut
  /// The OS refused (an errno, or a Winsock error on Windows), with its description.
  case failed(code: Int32, String)

  /// The connection was refused: nothing listens on that port.
  public var isRefused: Bool {
    if case .failed(let code, _) = self { return code == Sockets.connectionRefused }
    return false
  }
}

/// TCP sockets polled together with libssh2 and `PollWaker`, with BSD sockets or Winsock. Sockets are
/// non-blocking once connected (a listener blocks in `accept`); results report would-block instead of an errno.
public enum Sockets {
  #if os(Windows)
    public static let invalid: SocketHandle = INVALID_SOCKET
    public static let readable = Int16(POLLRDNORM)
    public static let writable = Int16(POLLWRNORM)
    public static let connectionRefused = Int32(WSAECONNREFUSED)
    public static let connectionReset = Int32(WSAECONNRESET)
  #else
    public static let invalid: SocketHandle = -1
    public static let readable = Int16(POLLIN)
    public static let writable = Int16(POLLOUT)
    public static let connectionRefused = ECONNREFUSED
    public static let connectionReset = ECONNRESET
  #endif
  /// Reported in `revents`: the peer hung up, an error, or the socket isn't open. (Asking for them is optional:
  /// `descriptor` drops them where poll would refuse them, Windows.)
  public static let hangUp = Int16(POLLHUP | POLLERR | POLLNVAL)

  public static func startup() { _ = started }

  private static let started: Bool = {
    #if os(Windows)
      var data = WSADATA()
      return WSAStartup(0x0202, &data) == 0
    #else
      return true
    #endif
  }()

  public static func descriptor(_ socket: SocketHandle, events: Int16) -> PollDescriptor {
    #if os(Windows)
      PollDescriptor(fd: socket, events: events & (readable | writable), revents: 0)
    #else
      PollDescriptor(fd: socket, events: events, revents: 0)
    #endif
  }

  /// Waits up to `milliseconds` for one of `descriptors` to be ready; the number ready.
  @discardableResult
  public static func poll(_ descriptors: inout [PollDescriptor], milliseconds: Int32) -> Int32 {
    #if os(Windows)
      WSAPoll(&descriptors, ULONG(descriptors.count), milliseconds)
    #else
      Darwin.poll(&descriptors, nfds_t(descriptors.count), milliseconds)
    #endif
  }

  /// Waits up to `milliseconds` for `socket` to be ready for `events`; what happened (`revents`), 0 on timeout.
  @discardableResult
  public static func wait(_ socket: SocketHandle, for events: Int16, milliseconds: Int32) -> Int16 {
    var descriptors = [descriptor(socket, events: events)]
    return poll(&descriptors, milliseconds: milliseconds) > 0 ? descriptors[0].revents : 0
  }

  public static func close(_ socket: SocketHandle) {
    #if os(Windows)
      _ = closesocket(socket)
    #else
      _ = Darwin.close(socket)
    #endif
  }

  /// No more bytes go out; the peer reads an end.
  public static func shutdownWrite(_ socket: SocketHandle) {
    #if os(Windows)
      _ = shutdown(socket, Int32(SD_SEND))
    #else
      _ = Darwin.shutdown(socket, SHUT_WR)
    #endif
  }

  public static func setNonBlocking(_ socket: SocketHandle) {
    #if os(Windows)
      var mode: u_long = 1
      _ = ioctlsocket(socket, Int32(bitPattern: 0x8004_667E), &mode)  // FIONBIO
    #else
      _ = fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) | O_NONBLOCK)
    #endif
  }

  static func setOption(_ socket: SocketHandle, level: Int32, name: Int32, value: Int32) {
    var value = value
    #if os(Windows)
      withUnsafePointer(to: &value) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 4) { _ = setsockopt(socket, level, name, $0, 4) }
      }
    #else
      _ = setsockopt(socket, level, name, &value, socklen_t(MemoryLayout<Int32>.size))
    #endif
  }

  /// TCP_NODELAY: small writes (keystrokes) go out at once.
  static func setNoDelay(_ socket: SocketHandle) {
    #if os(Windows)
      setOption(socket, level: Int32(IPPROTO_TCP.rawValue), name: TCP_NODELAY, value: 1)
    #else
      setOption(socket, level: IPPROTO_TCP, name: TCP_NODELAY, value: 1)
    #endif
  }

  /// The socket's pending error (`SO_ERROR`), 0 if none.
  public static func pendingError(_ socket: SocketHandle) -> Int32 {
    var error: Int32 = 0
    #if os(Windows)
      var length: Int32 = 4
      withUnsafeMutablePointer(to: &error) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 4) { _ = getsockopt(socket, SOL_SOCKET, SO_ERROR, $0, &length) }
      }
    #else
      var length = socklen_t(MemoryLayout<Int32>.size)
      getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length)
    #endif
    return error
  }

  /// The last socket call's error.
  public static var lastError: Int32 {
    #if os(Windows)
      WSAGetLastError()
    #else
      errno
    #endif
  }

  private static var wouldBlock: Bool {
    #if os(Windows)
      WSAGetLastError() == WSAEWOULDBLOCK
    #else
      errno == EAGAIN || errno == EWOULDBLOCK
    #endif
  }

  /// TCP keepalive: probe an idle link after `idle` seconds of quiet, every `interval` seconds, and give up after
  /// `count` unanswered probes, so a peer that vanished without closing turns into a socket error.
  public struct KeepAlive: Sendable {
    public var idle: Int32
    public var interval: Int32
    public var count: Int32

    public init(idle: Int32, interval: Int32, count: Int32) {
      self.idle = idle
      self.interval = interval
      self.count = count
    }
  }

  static func setKeepAlive(_ socket: SocketHandle, _ keepAlive: KeepAlive) {
    setOption(socket, level: SOL_SOCKET, name: SO_KEEPALIVE, value: 1)
    #if os(Windows)
      let tcp = Int32(IPPROTO_TCP.rawValue)
      setOption(socket, level: tcp, name: 3, value: keepAlive.idle)  // TCP_KEEPIDLE
      setOption(socket, level: tcp, name: 17, value: keepAlive.interval)  // TCP_KEEPINTVL
      setOption(socket, level: tcp, name: 16, value: keepAlive.count)  // TCP_KEEPCNT
    #else
      setOption(socket, level: IPPROTO_TCP, name: TCP_KEEPALIVE, value: keepAlive.idle)
      setOption(socket, level: IPPROTO_TCP, name: TCP_KEEPINTVL, value: keepAlive.interval)
      setOption(socket, level: IPPROTO_TCP, name: TCP_KEEPCNT, value: keepAlive.count)
    #endif
  }

  /// A TCP connection to `host`, non-blocking once connected.
  public static func connect(
    host: String, port: Int, timeout: TimeInterval, keepAlive: KeepAlive? = nil
  ) throws(SocketError) -> SocketHandle {
    startup()
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    #if os(Windows)
      hints.ai_socktype = Int32(SOCK_STREAM)
    #else
      hints.ai_socktype = SOCK_STREAM
    #endif
    var info: UnsafeMutablePointer<addrinfo>?
    let rc = getaddrinfo(host, String(port), &hints, &info)
    guard rc == 0, let first = info else { throw .hostNotFound(resolverError(rc)) }
    defer { freeaddrinfo(first) }
    var lastError = SocketError.timedOut
    var candidate: UnsafeMutablePointer<addrinfo>? = first
    while let address = candidate {
      candidate = address.pointee.ai_next
      let fd = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
      if fd == invalid { continue }
      setNoDelay(fd)
      #if !os(Windows)
        setOption(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
      #endif
      if let keepAlive { setKeepAlive(fd, keepAlive) }
      setNonBlocking(fd)
      #if os(Windows)
        let connected = WinSDK.connect(fd, address.pointee.ai_addr, Int32(address.pointee.ai_addrlen)) == 0
        let inProgress = !connected && WSAGetLastError() == WSAEWOULDBLOCK
      #else
        let connected = Darwin.connect(fd, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0
        let inProgress = !connected && (errno == EINPROGRESS || errno == EALREADY)
      #endif
      if connected { return fd }
      if inProgress {
        if wait(fd, for: writable, milliseconds: Int32(timeout * 1000)) != 0 {
          let error = pendingError(fd)
          if error == 0 { return fd }
          lastError = .failed(code: error, describe(error))
        } else {
          lastError = .timedOut
        }
      } else {
        let error = Self.lastError
        lastError = .failed(code: error, describe(error))
      }
      close(fd)
    }
    throw lastError
  }

  /// A blocking TCP listener on `host:port` (port 0: any free port), and the port it got.
  public static func listen(host: String, port: Int) throws(SocketError) -> (socket: SocketHandle, port: Int) {
    startup()
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_flags = AI_PASSIVE
    #if os(Windows)
      hints.ai_socktype = Int32(SOCK_STREAM)
    #else
      hints.ai_socktype = SOCK_STREAM
    #endif
    var info: UnsafeMutablePointer<addrinfo>?
    let rc = getaddrinfo(host.isEmpty ? nil : host, String(port), &hints, &info)
    guard rc == 0, let first = info else { throw .hostNotFound(resolverError(rc)) }
    defer { freeaddrinfo(first) }
    var lastError = SocketError.failed(code: 0, "no address to listen on")
    var candidate: UnsafeMutablePointer<addrinfo>? = first
    while let address = candidate {
      candidate = address.pointee.ai_next
      let fd = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
      if fd == invalid { continue }
      #if os(Windows)
        // Windows' SO_REUSEADDR lets another socket take the port; exclusive use is its default's opposite.
        setOption(fd, level: SOL_SOCKET, name: ~Int32(SO_REUSEADDR), value: 1)  // SO_EXCLUSIVEADDRUSE
        let bound = WinSDK.bind(fd, address.pointee.ai_addr, Int32(address.pointee.ai_addrlen)) == 0
          && WinSDK.listen(fd, 16) == 0
      #else
        setOption(fd, level: SOL_SOCKET, name: SO_REUSEADDR, value: 1)
        let bound = Darwin.bind(fd, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0 && Darwin.listen(fd, 16) == 0
      #endif
      if bound { return (fd, localPort(fd)) }
      let error = Self.lastError
      lastError = .failed(code: error, describe(error))
      close(fd)
    }
    throw lastError
  }

  /// The next connection to `listener`, non-blocking with TCP_NODELAY; nil once the listener is closed.
  public static func accept(_ listener: SocketHandle) -> SocketHandle? {
    while true {
      #if os(Windows)
        let client = WinSDK.accept(listener, nil, nil)
      #else
        let client = Darwin.accept(listener, nil, nil)
        if client < 0 && errno == EINTR { continue }
      #endif
      guard client != invalid else { return nil }
      setNonBlocking(client)
      setNoDelay(client)
      #if !os(Windows)
        setOption(client, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
      #endif
      return client
    }
  }

  /// What a non-blocking read or write did.
  public enum Transfer: Equatable, Sendable {
    /// This many bytes moved.
    case bytes(Int)
    /// Nothing can move now; poll and try again.
    case wouldBlock
    /// The peer closed (a read only).
    case closed
    /// The connection failed with this error.
    case failed(Int32)
  }

  public static func receive(_ socket: SocketHandle, into buffer: UnsafeMutableRawBufferPointer) -> Transfer {
    #if os(Windows)
      let count = Int(recv(socket, buffer.baseAddress?.assumingMemoryBound(to: CChar.self), Int32(buffer.count), 0))
    #else
      let count = Darwin.recv(socket, buffer.baseAddress, buffer.count, 0)
    #endif
    if count > 0 { return .bytes(count) }
    if count == 0 { return .closed }
    return wouldBlock ? .wouldBlock : .failed(lastError)
  }

  public static func send(_ socket: SocketHandle, _ buffer: UnsafeRawBufferPointer) -> Transfer {
    #if os(Windows)
      let count = Int(WinSDK.send(socket, buffer.baseAddress?.assumingMemoryBound(to: CChar.self), Int32(buffer.count), 0))
    #else
      let count = Darwin.send(socket, buffer.baseAddress, buffer.count, 0)
    #endif
    if count >= 0 { return .bytes(count) }
    return wouldBlock ? .wouldBlock : .failed(lastError)
  }

  /// The address and port of the socket's peer ("127.0.0.1", 0 when unknown).
  public static func peerAddress(_ socket: SocketHandle) -> (host: String, port: Int) {
    var address = sockaddr_in()
    #if os(Windows)
      var length = Int32(MemoryLayout<sockaddr_in>.size)
    #else
      var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    #endif
    let ok = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(socket, $0, &length) == 0 }
    }
    guard ok, Int32(address.sin_family) == AF_INET else { return ("127.0.0.1", 0) }
    var text = [CChar](repeating: 0, count: 16)
    _ = inet_ntop(AF_INET, &address.sin_addr, &text, 16)
    return (String(cString: text), Int(UInt16(bigEndian: address.sin_port)))
  }

  private static func localPort(_ socket: SocketHandle) -> Int {
    var address = sockaddr_in()
    #if os(Windows)
      var length = Int32(MemoryLayout<sockaddr_in>.size)
    #else
      var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    #endif
    _ = withUnsafeMutablePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(socket, $0, &length) }
    }
    return Int(UInt16(bigEndian: address.sin_port))
  }

  private static func resolverError(_ code: Int32) -> String {
    #if os(Windows)
      "error \(code)"
    #else
      String(cString: gai_strerror(code))
    #endif
  }

  /// A socket error's description.
  public static func describe(_ error: Int32) -> String {
    #if os(Windows)
      switch error {
      case WSAECONNREFUSED: "Connection refused"
      case WSAECONNRESET: "Connection reset by peer"
      case WSAECONNABORTED: "Software caused connection abort"
      case WSAETIMEDOUT: "Operation timed out"
      case WSAEHOSTUNREACH: "No route to host"
      case WSAENETUNREACH: "Network is unreachable"
      case WSAEADDRINUSE: "Address already in use"
      case WSAEACCES: "Permission denied"
      default: "Socket error \(error)"
      }
    #else
      String(cString: strerror(error))
    #endif
  }
}

/// Wakes a thread sleeping in `poll`: add `fd` to its poll set, call `wake` from any thread, and `drain` after
/// waking. A pipe; on Windows, where only sockets poll, a loopback UDP socket connected to itself.
public final class PollWaker: @unchecked Sendable {
  private let lock = NSLock()
  #if os(Windows)
    private var socket: SocketHandle = Sockets.invalid
  #else
    private var ends: [Int32] = [-1, -1]
  #endif

  public init() {
    #if os(Windows)
      Sockets.startup()
      let fd = WinSDK.socket(AF_INET, Int32(SOCK_DGRAM), Int32(IPPROTO_UDP.rawValue))
      guard fd != Sockets.invalid else { return }
      var address = sockaddr_in()
      address.sin_family = ADDRESS_FAMILY(AF_INET)
      address.sin_addr.S_un.S_addr = u_long(0x7F00_0001).bigEndian
      var length = Int32(MemoryLayout<sockaddr_in>.size)
      let bound = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
          bind(fd, address, length) == 0 && getsockname(fd, address, &length) == 0
            && WinSDK.connect(fd, address, length) == 0
        }
      }
      guard bound else {
        Sockets.close(fd)
        return
      }
      Sockets.setNonBlocking(fd)
      socket = fd
    #else
      if pipe(&ends) == 0 {
        for end in ends { _ = fcntl(end, F_SETFL, fcntl(end, F_GETFL) | O_NONBLOCK) }
      } else {
        ends = [-1, -1]
      }
    #endif
  }

  /// The socket or pipe end to poll for reading (`Sockets.invalid` if it couldn't be made).
  public var fd: SocketHandle {
    lock.lock()
    defer { lock.unlock() }
    #if os(Windows)
      return socket
    #else
      return ends[0]
    #endif
  }

  public var isValid: Bool { fd != Sockets.invalid }

  public func wake() {
    lock.lock()
    defer { lock.unlock() }
    var byte: UInt8 = 1
    #if os(Windows)
      guard socket != Sockets.invalid else { return }
      withUnsafePointer(to: &byte) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: 1) { _ = send(socket, $0, 1, 0) }
      }
    #else
      guard ends[1] >= 0 else { return }
      _ = Darwin.write(ends[1], &byte, 1)
    #endif
  }

  public func drain() {
    let fd = self.fd
    guard fd != Sockets.invalid else { return }
    var sink = [CChar](repeating: 0, count: 64)
    #if os(Windows)
      while recv(fd, &sink, Int32(sink.count), 0) > 0 {}
    #else
      while Darwin.read(fd, &sink, sink.count) > 0 {}
    #endif
  }

  public func close() {
    lock.lock()
    defer { lock.unlock() }
    #if os(Windows)
      if socket != Sockets.invalid { Sockets.close(socket) }
      socket = Sockets.invalid
    #else
      for end in ends where end >= 0 { Darwin.close(end) }
      ends = [-1, -1]
    #endif
  }

  deinit { close() }
}
