import "dart:typed_data";

class TLV {
  List<int> tag;
  List<int> value;

  TLV({required this.tag, required this.value});

  bool isConstructed() {
    return (tag[0] & 0x20) != 0;
  }

  Uint8List get data {
    return Uint8List.fromList([...tag, ...length, ...value]);
  }

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
