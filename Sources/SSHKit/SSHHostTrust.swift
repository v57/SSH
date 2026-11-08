import Foundation

/// What a server showed in the handshake, before anything of the user's has been sent to it.
public struct SSHHostKey: Sendable, Hashable {
  /// The server as the app named it (`SSHServer.host`).
  public var host: String
  public var port: Int
  /// The address that answered: `host`, or one of its fallbacks.
  public var address: String
  /// `SHA256:…`.
  public var fingerprint: String
  /// "ECDSA P-256", "RSA"…
  public var type: String

  public init(host: String, port: Int, address: String, fingerprint: String, type: String) {
    self.host = host
    self.port = port
    self.address = address
    self.fingerprint = fingerprint
    self.type = type
  }
}

/// How a login decides about a server's host key. `SSHServer` can't be made without one, so an app can't trust a
/// server by leaving something out. No password is sent and nothing is signed until the decision is yes.
public enum SSHHostTrust: Sendable {
  /// Only this key (`SHA256:…`): one the user accepted before, or one from a verified source, such as a key a Hub
  /// device signed. Any other key fails with `SSHTunnelError.hostKeyChanged`.
  case pinned(String)
  /// Nothing is known about this server, and someone can answer: `decide` gets the key after the handshake and says
  /// whether to go on (only when the server's own address answered, never a fallback), and remembers the key if it says yes. Waits two minutes at most (servers drop a login after about as long), and no answer is a no.
  case ask(@Sendable (SSHHostKey) async -> Bool)
  /// Nothing is known about this server and nobody can answer (a background job, a command-line tool): an unknown key
  /// fails with `SSHTunnelError.hostKeyUnverified`.
  case refuseUnknown

  /// `.pinned` when there's a fingerprint, else `unknown`: what to do for a server met the first time.
  public static func known(_ fingerprint: String?, otherwise unknown: SSHHostTrust) -> SSHHostTrust {
    if let fingerprint, !fingerprint.isEmpty { return .pinned(fingerprint) }
    return unknown
  }

  /// The longest `ask` waits for its answer.
  static let answerTimeout: TimeInterval = 120
}

/// The host keys of the big code hosts, shipped with the app so the first connection to them asks nothing and can't
/// be answered by anyone else. These win over what an app knows: another key there is refused, and asking wouldn't
/// help, since nobody can tell a stranger's key from a real one by looking at it.
///
/// A new key at one of these needs a new build, as it does for a browser's pinned certificates. Taken on 2026-11-04 from
/// the sites' own pages, and each matched what the server sent (`ssh-keyscan`):
/// - GitHub: https://api.github.com/meta (`ssh_key_fingerprints`) and
///   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
/// - GitLab: https://docs.gitlab.com/user/gitlab_com/ ("SSH host keys fingerprints")
/// - Bitbucket: https://bitbucket.org/site/ssh (the key lines, hashed by `ssh-keygen -lf`) and
///   https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/
public enum SSHKnownHosts {
  private static let github: Set<String> = [
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",  // Ed25519
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",  // ECDSA
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",  // RSA
  ]
  private static let gitlab: Set<String> = [
    "SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8",  // Ed25519
    "SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw",  // ECDSA
    "SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ",  // RSA
  ]
  private static let bitbucket: Set<String> = [
    "SHA256:ybgmFkzwOSotHTHLJgHO0QN8L0xErw6vd0VhFA9m3SM",  // Ed25519
    "SHA256:FC73VB6C4OQLSCrjEayhMp9UMxS97caD/Yyi2bhW/J0",  // ECDSA
    "SHA256:46OSHA1Rmj8E8ERTC6xkNcmGOw9oFxYr0WF6zWW8l1E",  // RSA
  ]
  private static let hosts: [String: Set<String>] = [
    "github.com:22": github, "ssh.github.com:443": github,
    "gitlab.com:22": gitlab, "altssh.gitlab.com:443": gitlab,
    "bitbucket.org:22": bitbucket, "ssh.bitbucket.org:22": bitbucket,
  ]

  /// The keys shipped for a server, nil when none are.
  public static func fingerprints(host: String, port: Int) -> Set<String>? {
    var name = host.lowercased()
    if name.hasSuffix(".") { name.removeLast() }
    return hosts["\(name):\(port)"]
  }
}

extension SSHServer {
  /// Decides about the key the server showed, throwing when the login mustn't go on. Runs before authentication, on
  /// the session's own thread, which an `ask` holds until it's answered.
  public func verify(_ key: SSHHostKey) throws {
    if let published = SSHKnownHosts.fingerprints(host: host, port: port) {
      guard published.contains(key.fingerprint) else {
        throw SSHTunnelError.hostKeyNotPublished(host: host, actual: key.fingerprint)
      }
      return
    }
    switch trust {
    case .pinned(let known):
      guard known == key.fingerprint else {
        throw SSHTunnelError.hostKeyChanged(expected: known, actual: key.fingerprint)
      }
    case .refuseUnknown:
      throw SSHTunnelError.hostKeyUnverified(host: host, fingerprint: key.fingerprint)
    case .ask(let decide):
      // Only the server's own address is asked about: a fallback (a Bonjour name, a Hub overlay address) is trusted
      // only with a pin, so nobody on the network can answer for it and be accepted under the host's name (M7).
      guard key.address.isEmpty || key.address.lowercased() == host.lowercased() else {
        throw SSHTunnelError.hostKeyFromFallback(host: host, address: key.address, fingerprint: key.fingerprint)
      }
      guard Self.answer(of: decide, about: key) else {
        throw SSHTunnelError.hostKeyRejected(host: host, fingerprint: key.fingerprint)
      }
    }
  }

  private static func answer(of decide: @escaping @Sendable (SSHHostKey) async -> Bool, about key: SSHHostKey) -> Bool {
    let answered = DispatchSemaphore(value: 0)
    let box = Answer()
    let task = Task.detached {
      box.set(await decide(key))
      answered.signal()
    }
    guard answered.wait(timeout: .now() + SSHHostTrust.answerTimeout) == .success else {
      task.cancel()
      return false
    }
    return box.value
  }

  private final class Answer: @unchecked Sendable {
    private let lock = NSLock()
    private var answer = false
    var value: Bool { lock.withLock { answer } }
    func set(_ value: Bool) { lock.withLock { answer = value } }
  }
}
