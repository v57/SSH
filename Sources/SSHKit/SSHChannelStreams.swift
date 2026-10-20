import CLibssh2
import Foundation
import WireKit

/// Byte streams to `host:port` over `direct-tcpip` channels of one logged-in libssh2 session: what `ssh -L` does,
/// without the local port. Clients talk to the SSH session in this process, so no other app or user can reach the
/// database through it.
///
/// libssh2 isn't thread-safe per session: any thread asks for a stream (`open`, `dialer`), and only the thread that
/// owns the session calls `pump` (whenever `onActivity` asks, and on its usual ticks) and `closeAll`.
public final class SSHChannelStreams: @unchecked Sendable {
  private let onActivity: @Sendable () -> Void
  private let lock = NSLock()
  private var requests: [Request] = []
  private var closedReason: String?

  /// Only touched on the owner thread.
  private var streams: [Stream] = []

  private static let eagain = Int32(LIBSSH2_ERROR_EAGAIN)

  /// `onActivity` wakes the owner thread: a stream was asked for, or has bytes to send.
  public init(onActivity: @escaping @Sendable () -> Void) {
    self.onActivity = onActivity
  }

  /// Clients that connect through these streams; TLS goes on top of the channel when a client asks for it.
  public var dialer: WireDialer {
    WireDialer.streams { [self] host, port, timeout in try await open(host: host, port: port, timeout: timeout) }
  }

  /// A stream to `host:port` as the SSH server sees it ("127.0.0.1" is the server itself).
  public func open(host: String, port: Int, timeout: TimeInterval = 15) async throws -> WireChannel {
    try await withCheckedThrowingContinuation { continuation in
      lock.lock()
      if let reason = closedReason {
        lock.unlock()
        continuation.resume(throwing: WireError.connectionFailed(reason))
        return
      }
      requests.append(
        Request(host: host, port: port, deadline: Date().addingTimeInterval(timeout), continuation: continuation))
      lock.unlock()
      onActivity()
    }
  }

  // MARK: Owner thread

  /// Whether a channel has bytes waiting for the SSH socket to take them (poll it for writing).
  public var wantsSocketOut: Bool {
    streams.contains { !$0.toChannel.isEmpty }
  }

  /// Opens the channels asked for and moves bytes both ways. Call it on the thread that owns `session`.
  public func pump(session: OpaquePointer) {
    openRequested(session)
    for stream in streams where !stream.closed { move(stream, session: session) }
    streams.removeAll { $0.closed }
  }

  /// Ends every stream (with `reason` for the app) and frees their channels; the session must still exist. Later
  /// `open` calls fail with `reason`.
  public func closeAll(reason: String) {
    lock.lock()
    closedReason = reason
    let waiting = requests
    requests = []
    lock.unlock()
    for request in waiting { request.continuation.resume(throwing: WireError.connectionFailed(reason)) }
    for stream in streams {
      free(stream)
      stream.pipe.finish(.connectionFailed(reason))
    }
    streams = []
  }

  /// Opens channels in the order asked for. A non-blocking open that can't finish yet must be retried with the
  /// same arguments before libssh2 starts another, so the rest wait behind it.
  private func openRequested(_ session: OpaquePointer) {
    lock.lock()
    var pending = requests
    requests = []
    lock.unlock()
    while let request = pending.first {
      let channel = request.host.withCString { host in
        libssh2_channel_direct_tcpip_ex(session, host, Int32(request.port), "127.0.0.1", 0)
      }
      if let channel {
        pending.removeFirst()
        let pipe = WireChannel(onActivity: onActivity)
        streams.append(Stream(channel: channel, pipe: pipe))
        request.continuation.resume(returning: pipe)
      } else if libssh2_session_last_errno(session) == Self.eagain {
        if Date() < request.deadline { break }
        pending.removeFirst()
        request.continuation.resume(
          throwing: WireError.timedOut("opening an SSH channel to \(request.host):\(request.port)"))
      } else {
        pending.removeFirst()
        request.continuation.resume(
          throwing: WireError.connectionFailed(
            "the SSH server refused to connect to \(request.host):\(request.port) (\(Self.lastError(session)))"))
      }
    }
    if !pending.isEmpty {
      lock.lock()
      requests = pending + requests
      lock.unlock()
    }
  }

  private func move(_ stream: Stream, session: OpaquePointer) {
    // Server → app, while the app keeps up.
    var buffer = [UInt8](repeating: 0, count: 32 * 1024)
    while stream.pipe.wantsInbound {
      let n = buffer.withUnsafeMutableBufferPointer { pointer in
        pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
          libssh2_channel_read_ex(stream.channel, 0, $0, pointer.count)
        }
      }
      if n > 0 {
        stream.pipe.deliver(Array(buffer[0..<Int(n)]))
      } else if n == 0 || Int32(n) == Self.eagain {
        break
      } else {
        stream.pipe.finish(.connectionFailed("the SSH channel broke (\(Self.lastError(session)))"))
        free(stream)
        return
      }
    }
    if libssh2_channel_eof(stream.channel) == 1 {
      // The server's side closed; the app reads what it was sent, then sees the end.
      stream.pipe.finish()
      free(stream)
      return
    }
    // App → server.
    stream.toChannel += stream.pipe.takeOutbound()
    while !stream.toChannel.isEmpty {
      let written = stream.toChannel.withUnsafeBufferPointer { pointer in
        pointer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pointer.count) {
          libssh2_channel_write_ex(stream.channel, 0, $0, pointer.count)
        }
      }
      if written > 0 {
        stream.toChannel.removeFirst(Int(written))
      } else if Int32(written) == Self.eagain {
        break
      } else {
        stream.pipe.finish(.connectionFailed("the SSH channel broke (\(Self.lastError(session)))"))
        free(stream)
        return
      }
    }
    if stream.pipe.isClosedByApp && stream.toChannel.isEmpty {
      _ = libssh2_channel_send_eof(stream.channel)
      free(stream)
    }
  }

  private func free(_ stream: Stream) {
    guard !stream.closed else { return }
    stream.closed = true
    _ = libssh2_channel_close(stream.channel)
    _ = libssh2_channel_free(stream.channel)
  }

  private static func lastError(_ session: OpaquePointer) -> String {
    var message: UnsafeMutablePointer<CChar>?
    var length: Int32 = 0
    _ = libssh2_session_last_error(session, &message, &length, 0)
    return message.map { String(cString: $0) } ?? "unknown error"
  }

  private struct Request {
    let host: String
    let port: Int
    let deadline: Date
    let continuation: CheckedContinuation<WireChannel, Error>
  }

  private final class Stream {
    let channel: OpaquePointer
    let pipe: WireChannel
    var toChannel: [UInt8] = []
    var closed = false

    init(channel: OpaquePointer, pipe: WireChannel) {
      self.channel = channel
      self.pipe = pipe
    }
  }
}
