import "package:scp03/src/tlv/tlv_parser.dart";
import "package:test/test.dart";

void main() {
  group("TLVParser", () {
    test("Parse short tag and length", () {
      final tlvs = TLVParser.parse([0x59, 0x02, 0x95, 0x02]);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, equals([0x59]));
      expect(tlv.value.length, equals(2));
      expect(tlv.value, equals([0x95, 0x02]));
      expect(tlv.isConstructed(), false);
    });

    test("Parse long tag and short length", () {
      final tlvs = TLVParser.parse([0x5F, 0x24, 0x03, 0x42, 0x42, 0x42]);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, equals([0x5F, 0x24]));
      expect(tlv.value.length, equals(3));
      expect(tlv.value, equals([0x42, 0x42, 0x42]));
      expect(tlv.isConstructed(), false);
    });

    test("Parse multiple TLVs", () {
      final tlvs = TLVParser.parse(
          [0x59, 0x02, 0x95, 0x02, 0x5F, 0x24, 0x03, 0x42, 0x42, 0x42]);
      expect(tlvs.length, equals(2));

      final do1 = tlvs[0];
      expect(do1.tag, equals([0x59]));
      expect(do1.value.length, equals(2));
      expect(do1.value, equals([0x95, 0x02]));

      final do2 = tlvs[1];
      expect(do2.tag, equals([0x5F, 0x24]));
      expect(do2.value.length, equals(3));
      expect(do2.value, equals([0x42, 0x42, 0x42]));
    });

    test("Parse long tag and long length (0x81)", () {
      final tag = [0x5F, 0x81, 0x7F]; // 0x81 is dummy
      final value = List.filled(255, 0x42);
      final tlvs = TLVParser.parse(tag + [0x81, 0xFF] + value);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, tag);
      expect(tlv.value.length, equals(255));
      expect(tlv.value, equals(value));
      expect(tlv.isConstructed(), false);
    });

    test("Parse long tag and long length (0x82)", () {
      final tag = [0x5F, 0x82, 0x7F]; // 0x82 is dummy
      final value = List.filled(256, 0x42);
      final tlvs = TLVParser.parse(tag + [0x82, 0x01, 0x00] + value);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, tag);
      expect(tlv.value.length, 256);
      expect(tlv.value, value);
      expect(tlv.isConstructed(), false);
    });

    test("Parse long tag and long length (0x83)", () {
      final tag = [0x5F, 0x83, 0x7F]; // 0x83 is dummy
      final value = List.filled(0x10000, 0x42);
      final tlvs = TLVParser.parse(tag + [0x83, 0x01, 0x00, 0x00] + value);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, tag);
      expect(tlv.value.length, 0x10000);
      expect(tlv.value, value);
      expect(tlv.isConstructed(), false);
    });

    test("Parse long tag and long length (0x84)", () {
      final tag = [0x5F, 0x84, 0x7F]; // 0x84 is dummy
      final value = List.filled(0x1000000, 0x42);
      final tlvs =
          TLVParser.parse(tag + [0x84, 0x01, 0x00, 0x00, 0x00] + value);
      expect(tlvs.length, equals(1));

      final tlv = tlvs[0];
      expect(tlv.tag, tag);
      expect(tlv.value.length, 0x1000000);
      expect(tlv.value, value);
      expect(tlv.isConstructed(), false);
    });

    test("Parse invalid TLV", () {
      final tlvs = TLVParser.parse([0x5F, 0x81, 0x24, 0x82, 0x01]);
      expect(tlvs.length, equals(0));
    });
  });
}
