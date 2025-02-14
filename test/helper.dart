import "dart:typed_data";

extension Bytes on String {
  Uint8List toBytes() {
    return Uint8List.fromList(codeUnits);
  }
}

Uint8List hex2bytes(String? hexString) {
  if (hexString == null) {
    return Uint8List(0);
  }
  hexString = hexString.replaceAll(RegExp(r"\s+"), "");
  hexString = hexString.replaceAll(RegExp(r"\n"), "");
  final len = hexString.length ~/ 2;
  final ret = Uint8List(len);
  for (var i = 0; i < len; i++) {
    ret[i] = int.parse(hexString.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return ret;
}
