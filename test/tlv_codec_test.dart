import "package:test/test.dart";
import "package:scp03/src/tlv/tlv.dart";
import "package:scp03/src/tlv/tlv_codec.dart";
import "dart:typed_data";

void main() {
  group("TLVCodec", () {
    test("encode", () {
      final tlvList = [
        TLV(tag: [0x5F, 0x24], value: [0x97, 0x03, 0x31]),
        TLV(tag: [0x5A], value: [0x01, 0x02])
      ];
      final codec = TLVCodec();
      final encoded = codec.encode(tlvList);
      expect(encoded,
          [0x5F, 0x24, 0x03, 0x97, 0x03, 0x31, 0x5A, 0x02, 0x01, 0x02]);
    });

    test("decode", () {
      final data = Uint8List.fromList(
          [0x5F, 0x24, 0x03, 0x97, 0x03, 0x31, 0x5A, 0x02, 0x01, 0x02]);
      final codec = TLVCodec();
      final decoded = codec.decode(data);
      expect(decoded.length, 2);
      expect(decoded[0].tag, [0x5F, 0x24]);
      expect(decoded[0].value, [0x97, 0x03, 0x31]);
      expect(decoded[1].tag, [0x5A]);
      expect(decoded[1].value, [0x01, 0x02]);
    });

    test("decode invalid data", () {
      final data = Uint8List.fromList([0x5F, 0x24]);
      final codec = TLVCodec();
      expect(() => codec.decode(data), throwsFormatException);
    });
  });
}
