import "dart:ffi" as ffi;
import "dart:typed_data";

import "package:ffi/ffi.dart";

import "ext.dart";

/// A class representing a Command APDU (Application Protocol Data Unit).
class CAPDU {
  final int cla;
  final int ins;
  final int p1;
  final int p2;
  final int lc;
  final List<int> data;
  final int? le;

  /// Creates a CAPDU object with the given parameters.
  CAPDU({
    required this.cla,
    required this.ins,
    required this.p1,
    required this.p2,
    required this.data,
  })  : lc = data.length,
        le = data.isEmpty ? null : 0;

  /// Returns the length of the CAPDU object.
  int get length => 4 + (lc == 0 ? 0 : 1) + data.length + (le == null ? 0 : 1);

  /// Converts the CAPDU object to a Uint8List.
  Uint8List toUint8List() {
    var buffer = Uint8List(length);
    buffer[0] = cla;
    buffer[1] = ins;
    buffer[2] = p1;
    buffer[3] = p2;
    if (data.isNotEmpty) {
      buffer[4] = lc;
      for (var i = 0; i < data.length; i++) {
        buffer[5 + i] = data[i];
      }
    }
    final le = this.le;
    if (le != null) {
      buffer[length - 1] = le;
    }
    return buffer;
  }

  /// Converts the CAPDU object to a pointer of unsigned characters.
  ffi.Pointer<ffi.UnsignedChar> toBytes() {
    var buffer = calloc<ffi.UnsignedChar>(length);
    buffer[0] = cla;
    buffer[1] = ins;
    buffer[2] = p1;
    buffer[3] = p2;
    buffer[4] = lc;
    if (data.isNotEmpty) {
      for (var i = 0; i < data.length; i++) {
        buffer[5 + i] = data[i];
      }
    }
    final le = this.le;
    if (le != null) {
      buffer[length - 1] = le;
    }
    return buffer;
  }

  /// Converts the CAPDU object to a hexadecimal string.
  String toHexString() => toUint8List().toHexString();

  @override
  String toString() {
    return "C_APDU{cla: ${cla.toHexString()} ins: ${ins.toHexString()} p1: ${p1.toHexString()} p2: ${p2.toHexString()} lc: ${lc.toHexString()} le: ${le?.toHexString() ?? "none"} data: ${data.toHexString()}}";
  }
}
