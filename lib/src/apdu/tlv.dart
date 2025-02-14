import "dart:typed_data";

// An encoder and decoder for BER-TLV data object of ISO/IEC 7816-4:2005
class TLV {
  List<int> tag;
  List<int> value;

  TLV({required this.tag, required this.value});

  bool isConstructed() {
    return (tag[0] & 0x20) != 0;
  }

  Uint8List get data {
    return Uint8List.fromList([...tag, ..._lengthBytes, ...value]);
  }

  Uint8List get _lengthBytes {
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

  static List<TLV> parse(List<int> data) {
    var tlvs = <TLV>[];
    for (var i = 0; i < data.length;) {
      final (tlv, offset) = _parseTLV(data, i);
      if (offset == 0) {
        break;
      }
      tlvs.add(tlv);
      i += offset;
    }
    return tlvs;
  }

  static (TLV, int) _parseTLV(List<int> data, int i) {
    // Tag
    List<int> tag = [];
    int offset = 0;
    final first = data[i];
    if ((first & 0x1f) == 0x1f) {
      // long tag field
      tag.add(first);
      offset += 1;
      while (data[i + offset] & 0x80 != 0) {
        tag.add(data[i + offset]);
        offset += 1;
      }
      tag.add(data[i + offset]);
      offset += 1;
    } else {
      // short tag field
      tag = [first];
      offset += 1;
    }

    if (i + offset >= data.length) {
      return (TLV(tag: [], value: []), 0);
    }

    // Length
    int length = 0;
    final len1 = data[i + offset];
    if (len1 < 0x80) {
      length = len1;
      offset += 1;
    } else if (len1 == 0x81) {
      if (i + offset + 1 >= data.length) return (TLV(tag: [], value: []), 0);
      length = data[i + offset + 1];
      offset += 2;
    } else if (len1 == 0x82) {
      if (i + offset + 2 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 8) + data[i + offset + 2];
      offset += 3;
    } else if (len1 == 0x83) {
      if (i + offset + 3 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 16) +
          (data[i + offset + 2] << 8) +
          data[i + offset + 3];
      offset += 4;
    } else if (len1 == 0x84) {
      if (i + offset + 4 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 24) +
          (data[i + offset + 2] << 16) +
          (data[i + offset + 3] << 8) +
          data[i + offset + 4];
      offset += 5;
    } else {
      return (TLV(tag: [], value: []), 0);
    }

    if (i + offset + length > data.length) {
      return (TLV(tag: [], value: []), 0);
    }

    // Value
    final value = data.sublist(i + offset, i + offset + length);

    return (TLV(tag: tag, value: value), offset + length);
  }
}
