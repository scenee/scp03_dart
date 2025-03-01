import "tlv.dart";

/// A parser class for TLV (Tag-Length-Value) data objects.
class TLVParser {
  /// Parses a list of bytes into a list of TLV objects.
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

  /// Parses a TLV object from a list of bytes starting at the given index.
  static (TLV, int) _parseTLV(List<int> data, int i) {
    final emptyTLV = TLV(tag: [], value: []);
    int offset = 0;

    if (i + offset >= data.length) return (emptyTLV, 0);

    // Parsing the tag
    final first = data[i];
    if ((first & 0x1f) == 0x1f) {
      // long tag field
      offset += 1;
      while (data[i + offset] & 0x80 != 0) {
        offset += 1;
      }
      offset += 1;
    } else {
      // short tag field
      offset += 1;
    }

    if (i + offset >= data.length) return (emptyTLV, 0);

    // Tag
    final tag = data.sublist(i, i + offset);

    // Paring the value length
    int length = 0;
    final lenFirst = data[i + offset];
    if (lenFirst < 0x80) {
      length = lenFirst;
      offset += 1;
    } else if (lenFirst == 0x81) {
      if (i + offset + 1 >= data.length) return (TLV(tag: [], value: []), 0);
      length = data[i + offset + 1];
      offset += 2;
    } else if (lenFirst == 0x82) {
      if (i + offset + 2 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 8) + data[i + offset + 2];
      offset += 3;
    } else if (lenFirst == 0x83) {
      if (i + offset + 3 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 16) +
          (data[i + offset + 2] << 8) +
          data[i + offset + 3];
      offset += 4;
    } else if (lenFirst == 0x84) {
      if (i + offset + 4 >= data.length) return (TLV(tag: [], value: []), 0);
      length = (data[i + offset + 1] << 24) +
          (data[i + offset + 2] << 16) +
          (data[i + offset + 3] << 8) +
          data[i + offset + 4];
      offset += 5;
    } else {
      return (emptyTLV, 0);
    }

    if (i + offset + length > data.length) return (emptyTLV, 0);

    // Value
    final value = data.sublist(i + offset, i + offset + length);

    return (TLV(tag: tag, value: value), offset + length);
  }
}
