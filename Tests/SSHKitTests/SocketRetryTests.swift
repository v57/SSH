import Foundation
import Testing

@testable import SSHKit

/// A dial that finds no route to the host is tried once more after a short wait (Code C-011, Database D-023).
struct SocketRetryTests {
  @Test func unreachableIsOnlyNoRouteOrNoNetwork() {
    #if !os(Windows)
      #expect(SocketError.failed(code: EHOSTUNREACH, "No route to host").isUnreachable)
      #expect(SocketError.failed(code: ENETUNREACH, "Network is unreachable").isUnreachable)
      #expect(!SocketError.failed(code: ECONNREFUSED, "Connection refused").isUnreachable)
    #endif
    #expect(!SocketError.timedOut.isUnreachable)
    #expect(!SocketError.hostNotFound("x").isUnreachable)
  }

  /// A documentation address (RFC 3849) has no route on most machines: the dial fails twice, the second time after
  /// the wait. Where it's routed and times out instead, there's nothing to check.
  @Test func anUnreachableAddressIsDialedTwice() {
    let started = Date()
    do {
      let socket = try Sockets.connect(host: "2001:db8::1", port: 22, timeout: 4)
      Sockets.close(socket)
    } catch {
      if error.isUnreachable { #expect(Date().timeIntervalSince(started) >= Sockets.unreachableRetryDelay) }
    }
  }
}
