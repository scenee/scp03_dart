import "package:test/test.dart";
import "package:scp03/src/apdu/tlv.dart";

void main() {
  group("TLV", () {
    test("isConstructed", () {
      final tlv = TLV(tag: [0x20], value: [0x01, 0x02]);
      expect(tlv.isConstructed(), isTrue);
    });

    test("data", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: [0x97, 0x03, 0x31]);
      expect(tlv.data, [0x5F, 0x24, 0x03, 0x97, 0x03, 0x31]);
    });

    test("lengthBytes single byte", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: List.filled(127, 0));
      expect(tlv.length, [0x7F]);
    });

    test("lengthBytes two bytes", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: List.filled(128, 0));
      expect(tlv.length, [0x81, 0x80]);
    });

    test("lengthBytes three bytes", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: List.filled(256, 0));
      expect(tlv.length, [0x82, 0x01, 0x00]);
    });

    test("lengthBytes four bytes", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: List.filled(65536, 0));
      expect(tlv.length, [0x83, 0x01, 0x00, 0x00]);
    });

    test("lengthBytes five bytes", () {
      final tlv = TLV(tag: [0x5F, 0x24], value: List.filled(16777216, 0));
      expect(tlv.length, [0x84, 0x01, 0x00, 0x00, 0x00]);
    });
  });
}
