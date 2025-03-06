import "dart:convert";
import "dart:typed_data";
import "tlv.dart";
import "tlv_parser.dart";

/// A codec for encoding and decoding TLV (Tag-Length-Value) data objects.
class TLVCodec extends Codec<List<TLV>, Uint8List> {
  @override
  Converter<Uint8List, List<TLV>> get decoder => _TLVDecoder();
  @override
  Converter<List<TLV>, Uint8List> get encoder => _TLVEncoder();
}

/// A converter that decodes a [Uint8List] into a list of [TLV] objects.
class _TLVDecoder extends Converter<Uint8List, List<TLV>> {
  @override

  /// Converts the [input] bytes into a list of [TLV] objects.
  ///
  /// Throws a [FormatException] if the input cannot be parsed as valid TLV data.
  List<TLV> convert(Uint8List input) {
    final tlvs = TLVParser.parse(input);
    if (tlvs.isEmpty) {
      throw FormatException("Invalid TLV data");
    }
    return tlvs;
  }
}

/// A converter that encodes a list of [TLV] objects into a [Uint8List].
class _TLVEncoder extends Converter<List<TLV>, Uint8List> {
  @override

  /// Converts the list of [TLV] [input] objects into a byte array.
  Uint8List convert(List<TLV> input) {
    return Uint8List.fromList(input.expand((tlv) => tlv.data).toList());
  }
}
