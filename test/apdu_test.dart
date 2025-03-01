import "package:test/test.dart";
import "package:scp03/src/apdu/capdu.dart";
import "package:scp03/src/apdu/rapdu.dart";
import "package:ffi/ffi.dart";
import "dart:ffi" as ffi;

void main() {
  group("CAPDU", () {
    test("toBytes", () {
      final capdu = CAPDU(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: [0x3F, 0x01],
        le: 0x00,
      );
      final bytes = capdu.toBytes();
      expect(
        bytes,
        [0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x01, 0x00],
      );
    });

    test("toNativePointer", () {
      final capdu = CAPDU(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: [0x3F, 0x01],
        le: 0x00,
      );
      final ptr = capdu.toNativePointer();
      expect(
        (ptr as ffi.Pointer<ffi.Uint8>).asTypedList(8),
        [0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x01, 0x00],
      );
      calloc.free(ptr);
    });

    test("toString", () {
      final capdu = CAPDU(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: [0x3F, 0x00],
        le: 0x00,
      );
      expect(capdu.toString(),
          "C_APDU{cla: 00 ins: a4 p1: 04 p2: 00 lc: 02 le: 00 data: 3f00}");
    });

    test("No data", () {
      final capdu = CAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: []);
      expect(capdu.toString(), "C_APDU{cla: 00 ins: a4 p1: 04 p2: 00}");
    });
  });

  group("RAPDU", () {
    test("fromBytes", () {
      final bytes = calloc<ffi.UnsignedChar>(5);
      bytes[0] = 0x61;
      bytes[1] = 0x62;
      bytes[2] = 0x63;
      bytes[3] = 0x90;
      bytes[4] = 0x00;
      final rapdu = RAPDU.fromNativePointer(bytes, 5);
      expect(rapdu.data, [0x61, 0x62, 0x63]);
      expect(rapdu.sw1, 0x90);
      expect(rapdu.sw2, 0x00);
      calloc.free(bytes);
    });

    test("toString", () {
      final rapdu = RAPDU(data: [0x61, 0x62, 0x63], sw1: 0x90, sw2: 0x00);
      expect(rapdu.toString(), "R_APDU {sw1: 90, sw2: 00, data: 616263}");
    });

    test("isOk", () {
      final rapdu = RAPDU(data: [0x61, 0x62, 0x63], sw1: 0x90, sw2: 0x00);
      expect(rapdu.isOk(), isTrue);
    });
  });
}
