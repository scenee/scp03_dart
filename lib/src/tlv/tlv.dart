import "dart:typed_data";

/// A class representing a TLV (Tag-Length-Value) data object.
///
/// The [int] values of all parameters are expected to be in the range of 0x00
/// to 0xFF. If they are over the range, the values will be truncated to the
/// range.
class TLV {
  List<int> tag;
  List<int> value;

  /// Creates a TLV object with the given tag and value.
  TLV({required this.tag, required this.value});

  /// Checks if the TLV object is constructed.
  ///
  /// If it's constructed, the value is a list of TLV objects. You can use
  /// the [TLVParser] to parse the value into a list of TLV objects.
  bool isConstructed() {
    return (tag[0] & 0x20) != 0;
  }

  /// Returns the TLV object as a byte array.
  Uint8List get data {
    return Uint8List.fromList([...tag, ...length, ...value]);
  }

  /// Returns the length of the TLV value as a byte array.
  ///
  /// The length field is encoded in BER-TLV format, not an integer value of the
  /// value length.
  Uint8List get length {
    final len = value.length;
    if (len < 0x80) {
      return Uint8List.fromList([len]);
    } else if (len < 0x100) {
      return Uint8List.fromList([0x81, len]);
    } else if (len < 0x10000) {
      return Uint8List.fromList([0x82, len >> 8, len & 0xff]);
    } else if (len < 0x1000000) {
      return Uint8List.fromList(
          [0x83, len >> 16, (len >> 8) & 0xff, len & 0xff]);
    } else {
      return Uint8List.fromList(
        [0x84, len >> 24, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff],
      );
    }
  }
}

extension TLVList on List<TLV> {
  /// Converts the list of TLV objects to a Uint8List.
  Uint8List toUint8List() {
    return Uint8List.fromList(map((e) => e.data).expand((e) => e).toList());
  }
}
