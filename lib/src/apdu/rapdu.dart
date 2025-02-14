import "dart:ffi" as ffi;
import "dart:typed_data";

import "ext.dart";

class RAPDU {
  final int sw1;
  final int sw2;
  final List<int> data;

  RAPDU({
    required this.data,
    required this.sw1,
    required this.sw2,
  });

  int get length => 2 + data.length;
  String get statusWord => "${sw1.toHexString()}${sw2.toHexString()}";

  @override
  String toString() {
    return "R_APDU {sw1: ${sw1.toHexString()}, sw2: ${sw2.toHexString()}, data: ${data.toHexString()}}";
  }

  static RAPDU fromBytes(ffi.Pointer<ffi.UnsignedChar> buffer, int length) {
    var sw1 = buffer[length - 2];
    var sw2 = buffer[length - 1];
    var data = <int>[];
    for (var i = 0; i < length - 2; i++) {
      data.add(buffer[i]);
    }
    return RAPDU(data: data, sw1: sw1, sw2: sw2);
  }

  String toHexString() => _toUint8List().toHexString();

  Uint8List _toUint8List() {
    var buffer = Uint8List(length);
    for (var i = 0; i < data.length; i++) {
      buffer[i] = data[i];
    }
    buffer[length - 2] = sw1;
    buffer[length - 1] = sw2;
    return buffer;
  }

  bool isOk() => sw1 == 0x90 && sw2 == 0x00;
}
