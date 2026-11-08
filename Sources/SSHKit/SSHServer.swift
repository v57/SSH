import Foundation

/// Where and how to log in over SSH.
public struct SSHServer: Sendable, Hashable {
  public var host: String
  /// Other addresses of the same machine, tried in order when `host` doesn't answer (a Mac's Bonjour name, its Hub
  /// Network address). The host key check is the same for all of them.
  public var fallbackHosts: [String]
  public var port: Int
  public var user: String
  public var password: String?
  public var key: SSHKey?
  /// What to do about the server's host key. Required: every login says who it trusts and who decides.
  public var trust: SSHHostTrust
  /// Nobody started this login just now (a check at launch, a scheduled job): a key that would have to ask the user fails
  /// the login instead. Not part of the login's identity: `==` and `hash` ignore it.
  public var unattended = false

  public init(
    host: String, fallbackHosts: [String] = [], port: Int = 22, user: String, password: String? = nil,
    key: SSHKey? = nil, trust: SSHHostTrust
  ) {
    self.host = host
    self.fallbackHosts = fallbackHosts
    self.port = port
    self.user = user
    self.password = password
    self.key = key
    self.trust = trust
  }

  /// The key this login accepts, when it's settled ahead of time (`SSHHostTrust.pinned`).
  public var knownFingerprint: String? {
    if case .pinned(let fingerprint) = trust { fingerprint } else { nil }
  }

  /// Every address to try, `host` first, each once.
  public var hosts: [String] {
    var seen = Set<String>()
    return ([host] + fallbackHosts).filter { !$0.isEmpty && seen.insert($0).inserted }
  }

  public static func == (a: SSHServer, b: SSHServer) -> Bool {
    a.host == b.host && a.fallbackHosts == b.fallbackHosts && a.port == b.port && a.user == b.user && a.password == b.password
      && a.hasSameKey(as: b) && a.knownFingerprint == b.knownFingerprint
      && a.asksAboutUnknownKeys == b.asksAboutUnknownKeys
  }

  private func hasSameKey(as other: SSHServer) -> Bool {
    switch (key, other.key) {
    case (nil, nil): true
    case (let a?, let b?): a.isSameKey(as: b)
    default: false
    }
  }

  private var asksAboutUnknownKeys: Bool {
    if case .ask = trust { true } else { false }
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
  /// Nothing is known about this server's key, and nobody can be asked.
  case hostKeyUnverified(host: String, fingerprint: String)
  /// The user said no, or didn't answer in time.
  case hostKeyRejected(host: String, fingerprint: String)
  /// Nothing is known about this server's key, and one of its other addresses answered: only its own address is asked
  /// about (security audit M7), since anyone on the network can answer for a `.local` name.
  case hostKeyFromFallback(host: String, address: String, fingerprint: String)
  /// A server whose keys ship with the app (`SSHKnownHosts`) showed another one.
  case hostKeyNotPublished(host: String, actual: String)
  case authenticationFailed(methods: String)
  case forwardFailed(String)
  case closed

  public var errorDescription: String? {
    switch self {
    case .connectFailed(let detail): "Couldn't reach the SSH server: \(detail)"
    case .handshakeFailed(let detail): "The SSH handshake failed: \(detail)"
    case .hostKeyChanged(let expected, let actual):
      "The SSH server's identity changed (was \(expected), now \(actual)). If you expected this, forget the saved host key and connect again."
    case .hostKeyUnverified(let host, let fingerprint):
      "\(host)'s SSH key hasn't been verified (\(fingerprint)), and this connection has no one to ask. Connect to it once from an app's window and check the key there."
    case .hostKeyRejected(let host, _):
      "The connection to \(host) was cancelled: its SSH key wasn't accepted, so nothing was sent to it."
    case .hostKeyFromFallback(let host, let address, _):
      "\(host) didn't answer, and its SSH key hasn't been accepted yet, so its other address \(address) wasn't trusted and nothing was sent to it. Connect once while \(host) itself answers, then the other addresses work too."
    case .hostKeyNotPublished(let host, let actual):
      "The server answering for \(host) showed an SSH key that isn't \(host)'s (\(actual)), so nothing was sent to it. Someone may be intercepting this connection. If \(host) has changed its keys, updating the app brings the new ones."
    case .authenticationFailed(let methods):
      "The SSH server didn't accept the key or password." + (methods.isEmpty ? "" : " It allows: \(methods).")
    case .forwardFailed(let detail): "The SSH server refused the tunnel: \(detail)"
    case .closed: "The SSH tunnel closed."
    }
  }
}
