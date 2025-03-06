import "tlv.dart";

/// A parser class for TLV (Tag-Length-Value) data objects.
class TLVParser {
  /// Parses a list of bytes into a list of TLV objects.
  static List<TLV> parse(List<int> data) {
    var tlvs = <TLV>[];
    for (var i = 0; i < data.length;) {
      final (tlv, numOfBytes) = _parseTLV(data, i);
      if (numOfBytes == 0) {
        break;
      }
      tlvs.add(tlv);
      i += numOfBytes;
    }
    return tlvs;
  }

  /// Parses a TLV object from a list of bytes starting at the given index.
  static (TLV, int) _parseTLV(List<int> data, int i) {
    final emptyTLV = TLV(tag: [], value: []);
    int numOfBytes = 0;

    if (i + numOfBytes >= data.length) return (emptyTLV, 0);

    // Parsing the tag
    final first = data[i];
    if ((first & 0x1f) == 0x1f) {
      // long tag field
      numOfBytes += 1;
      while (data[i + numOfBytes] & 0x80 != 0) {
        numOfBytes += 1;
      }
      numOfBytes += 1;
    } else {
      // short tag field
      numOfBytes += 1;
    }

    if (i + numOfBytes >= data.length) return (emptyTLV, 0);

    // Tag
    final tag = data.sublist(i, i + numOfBytes);

    // Paring the value length
    final (length, numOfLenBytes) = TLV.parseLengthBytes(data, i + numOfBytes);
    if (length < 0) {
      return (emptyTLV, 0);
    }
    numOfBytes += numOfLenBytes;

    if (i + numOfBytes + length > data.length) return (emptyTLV, 0);

    // Value
    final value = data.sublist(i + numOfBytes, i + numOfBytes + length);

    numOfBytes += length;

    return (TLV(tag: tag, value: value), numOfBytes);
  }
}
