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
  typealias PollDescriptor = WSAPOLLFD
#else
  public typealias SocketHandle = Int32
  typealias PollDescriptor = pollfd
#endif

/// The sockets the tunnel polls, with BSD sockets or Winsock.
enum Sockets {
  #if os(Windows)
    static let invalid: SocketHandle = INVALID_SOCKET
    static let readable = Int16(POLLRDNORM)
    static let writable = Int16(POLLWRNORM)
  #else
    static let invalid: SocketHandle = -1
    static let readable = Int16(POLLIN)
    static let writable = Int16(POLLOUT)
  #endif

  static func startup() { _ = started }

  private static let started: Bool = {
    #if os(Windows)
      var data = WSADATA()
      return WSAStartup(0x0202, &data) == 0
    #else
      return true
    #endif
  }()

  static func descriptor(_ socket: SocketHandle, events: Int16) -> PollDescriptor {
    PollDescriptor(fd: socket, events: events, revents: 0)
  }

  /// Waits up to `milliseconds` for one of `descriptors` to be ready; the number ready.
  @discardableResult
  static func poll(_ descriptors: inout [PollDescriptor], milliseconds: Int32) -> Int32 {
    #if os(Windows)
      WSAPoll(&descriptors, ULONG(descriptors.count), milliseconds)
    #else
      Darwin.poll(&descriptors, nfds_t(descriptors.count), milliseconds)
    #endif
  }

  static func close(_ socket: SocketHandle) {
    #if os(Windows)
      _ = closesocket(socket)
    #else
      _ = Darwin.close(socket)
    #endif
  }

  static func setNonBlocking(_ socket: SocketHandle) {
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

  static func pendingError(_ socket: SocketHandle) -> Int32 {
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

  /// A TCP connection to `host`, non-blocking once connected.
  static func connect(host: String, port: Int, timeout: TimeInterval) throws -> SocketHandle {
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
    guard rc == 0, let first = info else {
      throw SSHTunnelError.connectFailed("the host name \(host) couldn't be found")
    }
    defer { freeaddrinfo(first) }
    var lastError = "nothing answered"
    var candidate: UnsafeMutablePointer<addrinfo>? = first
    while let address = candidate {
      candidate = address.pointee.ai_next
      let fd = socket(address.pointee.ai_family, address.pointee.ai_socktype, address.pointee.ai_protocol)
      if fd == invalid { continue }
      #if os(Windows)
        setOption(fd, level: Int32(IPPROTO_TCP.rawValue), name: TCP_NODELAY, value: 1)
      #else
        setOption(fd, level: IPPROTO_TCP, name: TCP_NODELAY, value: 1)
        setOption(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
      #endif
      setNonBlocking(fd)
      #if os(Windows)
        let connected = WinSDK.connect(fd, address.pointee.ai_addr, Int32(address.pointee.ai_addrlen)) == 0
        let inProgress = !connected && WSAGetLastError() == WSAEWOULDBLOCK
      #else
        let connected = Darwin.connect(fd, address.pointee.ai_addr, address.pointee.ai_addrlen) == 0
        let inProgress = !connected && errno == EINPROGRESS
      #endif
      if connected { return fd }
      if inProgress {
        var descriptors = [descriptor(fd, events: writable)]
        if poll(&descriptors, milliseconds: Int32(timeout * 1000)) > 0 {
          let error = pendingError(fd)
          if error == 0 { return fd }
          lastError = isRefused(error) ? "connection refused (is SSH on?)" : describe(error)
        } else {
          lastError = "timed out"
        }
      } else {
        #if os(Windows)
          lastError = describe(WSAGetLastError())
        #else
          lastError = describe(errno)
        #endif
      }
      close(fd)
    }
    throw SSHTunnelError.connectFailed(lastError)
  }

  private static func isRefused(_ error: Int32) -> Bool {
    #if os(Windows)
      error == WSAECONNREFUSED
    #else
      error == ECONNREFUSED
    #endif
  }

  private static func describe(_ error: Int32) -> String {
    #if os(Windows)
      switch error {
      case WSAECONNREFUSED: "connection refused (is SSH on?)"
      case WSAETIMEDOUT: "timed out"
      case WSAEHOSTUNREACH, WSAENETUNREACH: "the host can't be reached"
      default: "socket error \(error)"
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

  var isValid: Bool { fd != Sockets.invalid }

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
