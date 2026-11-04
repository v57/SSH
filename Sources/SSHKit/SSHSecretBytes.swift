import Foundation
#if os(Windows)
  import WinSDK
#endif

/// Private key material in memory of its own, overwritten with zeros when the last key using it goes away.
///
/// A Swift array can't promise that: it moves and copies as it pleases and nothing clears the old storage. What's
/// wiped here is this one copy. A copy someone asked for (`SSHKey.privateBytes`), and what CryptoKit or Security make
/// while signing, are outside it.
final class SSHSecretBytes: @unchecked Sendable, ContiguousBytes {
  private let storage: UnsafeMutableRawBufferPointer
  private let release: (UnsafeMutableRawBufferPointer) -> Void

  /// `release` frees the memory, already zero; tests look at it first.
  init(_ bytes: [UInt8], release: @escaping (UnsafeMutableRawBufferPointer) -> Void = { $0.deallocate() }) {
    storage = .allocate(byteCount: bytes.count, alignment: 1)
    storage.copyBytes(from: bytes)
    self.release = release
  }

  deinit {
    Self.wipe(storage)
    release(storage)
  }

  var count: Int { storage.count }
  var array: [UInt8] { Array(storage) }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try body(UnsafeRawBufferPointer(storage))
  }

  /// Same bytes, without stopping at the first difference.
  func matches(_ other: SSHSecretBytes) -> Bool {
    guard count == other.count else { return false }
    return zip(storage, other.storage).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
  }

  /// Zeros that the compiler can't remove because nothing reads them afterwards.
  static func wipe(_ buffer: UnsafeMutableRawBufferPointer) {
    guard let base = buffer.baseAddress, buffer.count > 0 else { return }
    #if canImport(Darwin)
      _ = memset_s(base, buffer.count, 0, buffer.count)
    #elseif os(Windows)
      _ = RtlSecureZeroMemory(base, buffer.count)
    #else
      explicit_bzero(base, buffer.count)
    #endif
  }

  /// Clears a working copy before it's dropped: best effort, a copy the array made earlier stays as it was.
  static func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { wipe($0) }
  }
}
