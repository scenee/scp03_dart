import "dart:convert";
import "dart:typed_data";
import "tlv.dart";
import "tlv_parser.dart";

class TLVCodec extends Codec<List<TLV>, Uint8List> {
  @override
  Converter<Uint8List, List<TLV>> get decoder => _TLVDecoder();

  @override
  Converter<List<TLV>, Uint8List> get encoder => _TLVEncoder();
}

class _TLVDecoder extends Converter<Uint8List, List<TLV>> {
  @override
  List<TLV> convert(Uint8List input) {
    final tlvs = TLVParser.parse(input);
    if (tlvs.isEmpty) {
      throw FormatException("Invalid TLV data");
    }
    return tlvs;
  }
}

class _TLVEncoder extends Converter<List<TLV>, Uint8List> {
  @override
  Uint8List convert(List<TLV> input) {
    return Uint8List.fromList(input.expand((tlv) => tlv.data).toList());
  }
}
