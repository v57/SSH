import CLibssh2
import Foundation

/// What every libssh2 session here offers: what libssh2 was built with, in its own order, less what's broken or
/// retired (SHA-1 key exchange and signatures, CBC and older ciphers, MD5, RIPEMD-160 and SHA-1 MACs). A server that
/// has nothing else fails the handshake. Strict key exchange (Terrapin, CVE-2023-48795) stays on: libssh2 adds its
/// marker to any key exchange list.
public enum SSHAlgorithms {
  /// Call before the handshake.
  public static func restrict(_ session: OpaquePointer) {
    for method in methods {
      let allowed = supported(session, method: method).filter { isAllowed($0, method: method) }
      guard !allowed.isEmpty else { continue }
      _ = libssh2_session_method_pref(session, method, allowed.joined(separator: ","))
    }
  }

  static let methods = [
    LIBSSH2_METHOD_KEX, LIBSSH2_METHOD_HOSTKEY, LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC, LIBSSH2_METHOD_MAC_CS,
    LIBSSH2_METHOD_MAC_SC,
  ]

  static func isAllowed(_ name: String, method: Int32) -> Bool {
    switch method {
    case LIBSSH2_METHOD_KEX:
      // libssh2 puts its two markers in front of any list it's given.
      !name.contains("sha1") && name != "ext-info-c" && !name.hasPrefix("kex-strict-")
    case LIBSSH2_METHOD_HOSTKEY:
      !name.hasPrefix("ssh-rsa") && !name.hasPrefix("ssh-dss")
    case LIBSSH2_METHOD_CRYPT_CS, LIBSSH2_METHOD_CRYPT_SC:
      name != "none" && !["cbc", "3des", "arcfour", "blowfish", "cast128"].contains { name.contains($0) }
    case LIBSSH2_METHOD_MAC_CS, LIBSSH2_METHOD_MAC_SC:
      name != "none" && !["md5", "ripemd", "hmac-sha1"].contains { name.contains($0) }
    default:
      true
    }
  }

  /// What this build of libssh2 can do, in the order it prefers.
  static func supported(_ session: OpaquePointer, method: Int32) -> [String] {
    var names: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    let count = libssh2_session_supported_algs(session, method, &names)
    guard count > 0, let names else { return [] }
    defer { libssh2_free(session, names) }
    return (0..<Int(count)).compactMap { names[$0].map { String(cString: $0) } }
  }
}
