import "dart:ffi" as ffi;
import "dart:typed_data";

import "package:ffi_assist/ffi_assist.dart";

/// A class representing a Response APDU (Application Protocol Data Unit).
class RAPDU {
  final int sw1;
  final int sw2;
  final List<int> data;

  /// Creates a RAPDU object with the given parameters.
  RAPDU({
    required this.data,
    required this.sw1,
    required this.sw2,
  });

  /// Returns the length of the RAPDU object.
  int get length => 2 + data.length;

  /// Returns the status word of the RAPDU object as a hexadecimal string.
  String get statusWord => "${sw1.toHexString()}${sw2.toHexString()}";

  @override
  String toString() {
    return "R_APDU {sw1: ${sw1.toHexString()}, sw2: ${sw2.toHexString()}, data: ${data.toHexString()}}";
  }

  /// Creates a RAPDU object from a pointer of unsigned characters.
  static RAPDU fromNativePointer(
      ffi.Pointer<ffi.UnsignedChar> buffer, int length) {
    var sw1 = buffer[length - 2];
    var sw2 = buffer[length - 1];
    var data = <int>[];
    for (var i = 0; i < length - 2; i++) {
      data.add(buffer[i]);
    }
    return RAPDU(data: data, sw1: sw1, sw2: sw2);
  }

  /// Converts the RAPDU object to a Uint8List.
  Uint8List toBytes() {
    var buffer = Uint8List(length);
    for (var i = 0; i < data.length; i++) {
      buffer[i] = data[i];
    }
    buffer[length - 2] = sw1;
    buffer[length - 1] = sw2;
    return buffer;
  }

  /// Checks if the status word of this RAPDU object is '90 00'.
  bool isOk() => sw1 == 0x90 && sw2 == 0x00;
}
