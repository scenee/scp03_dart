import "package:scp03/src/apdu/tlv_parser.dart";
import "package:test/test.dart";

void main() {
  group("TLVParser", () {
    test("Parse short tag and length", () {
      final tlvs = TLVParser.parse([0x59, 0x02, 0x95, 0x02]);
      expect(tlvs.length, equals(1));

      final do1 = tlvs[0];
      expect(do1.tag, equals([0x59]));
      expect(do1.value.length, equals(2));
      expect(do1.value, equals([0x95, 0x02]));
      expect(do1.isConstructed(), false);
    });

    test("Parse long tag and short length", () {
      final tlvs = TLVParser.parse([0x5F, 0x24, 0x03, 0x97, 0x03, 0x31]);
      expect(tlvs.length, equals(1));

      final do2 = tlvs[0];
      expect(do2.tag, equals([0x5F, 0x24]));
      expect(do2.value.length, equals(3));
      expect(do2.value, equals([0x97, 0x03, 0x31]));
      expect(do2.isConstructed(), false);
    });

    test("Parse multiple TLVs", () {
      final tlvs = TLVParser.parse(
          [0x59, 0x02, 0x95, 0x02, 0x5F, 0x24, 0x03, 0x97, 0x03, 0x31]);
      expect(tlvs.length, equals(2));

      final do1 = tlvs[0];
      expect(do1.tag, equals([0x59]));
      expect(do1.value.length, equals(2));
      expect(do1.value, equals([0x95, 0x02]));

      final do2 = tlvs[1];
      expect(do2.tag, equals([0x5F, 0x24]));
      expect(do2.value.length, equals(3));
      expect(do2.value, equals([0x97, 0x03, 0x31]));
    });

    test("Parse long tag and long length", () {
      final tlvs = TLVParser.parse(
          [0x5F, 0x81, 0x24, 0x82, 0x01, 0x00] + List.filled(256, 0x97));
      expect(tlvs.length, equals(1));

      final do3 = tlvs[0];
      expect(do3.tag, equals([0x5F, 0x81, 0x24]));
      expect(do3.value.length, equals(256));
      expect(do3.value, equals(List.filled(256, 0x97)));
      expect(do3.isConstructed(), false);
    });

    test("Parse invalid TLV", () {
      final tlvs = TLVParser.parse([0x5F, 0x81, 0x24, 0x82, 0x01]);
      expect(tlvs.length, equals(0));
    });
  });
}
