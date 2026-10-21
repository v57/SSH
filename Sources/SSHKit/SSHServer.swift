import Foundation

/// Where and how to log in over SSH.
public struct SSHServer: Sendable, Hashable {
  public var host: String
  public var port: Int
  public var user: String
  public var password: String?
  public var key: SSHKey?
  /// The `SHA256:…` fingerprint seen before. `nil` trusts the first key the server shows.
  public var knownFingerprint: String?

  public init(
    host: String, port: Int = 22, user: String, password: String? = nil, key: SSHKey? = nil,
    knownFingerprint: String? = nil
  ) {
    self.host = host
    self.port = port
    self.user = user
    self.password = password
    self.key = key
    self.knownFingerprint = knownFingerprint
  }

  public static func == (a: SSHServer, b: SSHServer) -> Bool {
    a.host == b.host && a.port == b.port && a.user == b.user && a.password == b.password
      && a.key?.privateBytes == b.key?.privateBytes
      && (try? a.key?.publicKeyBlob()) == (try? b.key?.publicKeyBlob()) && a.knownFingerprint == b.knownFingerprint
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
  case authenticationFailed(methods: String)
  case forwardFailed(String)
  case closed

  public var errorDescription: String? {
    switch self {
    case .connectFailed(let detail): "Couldn't reach the SSH server: \(detail)"
    case .handshakeFailed(let detail): "The SSH handshake failed: \(detail)"
    case .hostKeyChanged(let expected, let actual):
      "The SSH server's identity changed (was \(expected), now \(actual)). If you expected this, forget the saved host key and connect again."
    case .authenticationFailed(let methods):
      "The SSH server didn't accept the key or password." + (methods.isEmpty ? "" : " It allows: \(methods).")
    case .forwardFailed(let detail): "The SSH server refused the tunnel: \(detail)"
    case .closed: "The SSH tunnel closed."
    }
  }
}
