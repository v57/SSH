import Foundation

/// SSH wire-format strings and mpints, and the byte writer and reader keys are encoded and decoded with.
enum SSHWire {
  static func string(_ w: inout Writer, _ bytes: [UInt8]) {
    w.writeBE(UInt32(bytes.count))
    w.write(bytes)
  }

  static func mpint(_ w: inout Writer, _ bytes: [UInt8]) {
    var payload = Array(bytes.drop { $0 == 0 })
    if let first = payload.first, first & 0x80 != 0 { payload.insert(0, at: 0) }
    string(&w, payload)
  }

  static func readString(_ r: inout Reader) throws -> [UInt8] {
    let length = Int(try r.readBE(UInt32.self))
    return try r.readBytes(length)
  }

  /// Appends big-endian values to a growing byte array.
  struct Writer {
    private(set) var bytes: [UInt8] = []

    var count: Int { bytes.count }

    mutating func write(_ byte: UInt8) { bytes.append(byte) }
    mutating func write<S: Sequence>(_ data: S) where S.Element == UInt8 { bytes.append(contentsOf: data) }

    mutating func writeBE<T: FixedWidthInteger>(_ value: T) {
      withUnsafeBytes(of: value.bigEndian) { bytes.append(contentsOf: $0) }
    }
  }

  /// Reads big-endian values from a byte array; a key cut short reads as an unrecognized one.
  struct Reader {
    let bytes: [UInt8]
    private(set) var offset: Int

    init(_ bytes: [UInt8], offset: Int = 0) {
      self.bytes = bytes
      self.offset = offset
    }

    var remaining: Int { bytes.count - offset }

    mutating func readByte() throws -> UInt8 {
      guard remaining >= 1 else { throw SSHKey.ImportError.unrecognized }
      defer { offset += 1 }
      return bytes[offset]
    }

    mutating func readBytes(_ n: Int) throws -> [UInt8] {
      guard n >= 0, remaining >= n else { throw SSHKey.ImportError.unrecognized }
      defer { offset += n }
      return Array(bytes[offset..<offset + n])
    }

    mutating func readBE<T: FixedWidthInteger>(_: T.Type = T.self) throws -> T {
      let size = MemoryLayout<T>.size
      guard remaining >= size else { throw SSHKey.ImportError.unrecognized }
      var value: T = 0
      for i in 0..<size { value = (value << 8) | T(truncatingIfNeeded: bytes[offset + i]) }
      offset += size
      return value
    }
  }
}
