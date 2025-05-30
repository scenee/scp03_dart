import "dart:ffi" as ffi;
import "dart:typed_data";

import "package:ffi/ffi.dart";
import "package:ffi_assist/ffi_assist.dart";

/// A class representing a Command APDU (Application Protocol Data Unit).
///
/// The [int] values of all parameters are expected to be in the range of 0x00
/// to 0xFF. If they are over the range, the values will be truncated to the
/// range.
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
    this.data = const [],
    this.le,
  }) : lc = data.length;

  /// Returns the length of the CAPDU object.
  int get length => 4 + (lc == 0 ? 0 : 1) + data.length + (le == null ? 0 : 1);

  /// Converts the CAPDU object to a Uint8List.
  Uint8List toBytes() {
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
      final le = this.le;
      if (le != null) {
        buffer[length - 1] = le;
      }
    }
    return buffer;
  }

  /// Converts the CAPDU object to a pointer of unsigned characters.
  ffi.Pointer<ffi.UnsignedChar> toNativePointer({
    ffi.Allocator allocator = calloc,
  }) {
    var buffer = allocator<ffi.UnsignedChar>(length);
    buffer[0] = cla;
    buffer[1] = ins;
    buffer[2] = p1;
    buffer[3] = p2;
    if (data.isNotEmpty) {
      buffer[4] = lc;
      for (var i = 0; i < data.length; i++) {
        buffer[5 + i] = data[i];
      }
      final le = this.le;
      if (le != null) {
        buffer[length - 1] = le;
      }
    }
    return buffer;
  }

  @override
  String toString() {
    if (data.isEmpty) {
      return "C_APDU{cla: ${cla.toHexString()} ins: ${ins.toHexString()} p1: ${p1.toHexString()} p2: ${p2.toHexString()}}";
    }
    return "C_APDU{cla: ${cla.toHexString()} ins: ${ins.toHexString()} p1: ${p1.toHexString()} p2: ${p2.toHexString()} lc: ${lc.toHexString()} le: ${le?.toHexString() ?? "none"} data: ${data.toHexString()}}";
  }
}
