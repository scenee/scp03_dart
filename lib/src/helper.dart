import "dart:typed_data";

extension HexStringUint8List on Uint8List {
  String toHexString([String separator = " "]) {
    return map((e) => e.toRadixString(16).padLeft(2, "0").toUpperCase())
        .join(separator);
  }

  bool equals(Uint8List other) {
    if (length != other.length) return false;

    for (int i = 0; i < other.length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}

extension HexStringList on List {
  String toHexString([String separator = ""]) {
    return map((e) => e.toRadixString(16).padLeft(2, "0").toUpperCase())
        .join(separator);
  }
}

extension HexStringInt on int {
  String toHexString([String separator = ""]) {
    return toRadixString(16).padLeft(2, "0").toUpperCase();
  }
}

bool listEquals<T>(List<T>? a, List<T>? b) {
  if (a == null) {
    return b == null;
  }
  if (b == null || a.length != b.length) {
    return false;
  }
  if (identical(a, b)) {
    return true;
  }
  for (int index = 0; index < a.length; index += 1) {
    if (a[index] != b[index]) {
      return false;
    }
  }
  return true;
}
