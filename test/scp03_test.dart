import "dart:typed_data";

import "package:ffi_assist/ffi_assist.dart";
import "package:scp03/scp03.dart";
import "package:test/test.dart";

import "crypto/scp03_crypto.dart";

final senc = hex2bytes("161886cb9ae7403d8dbccfe36b8a0426");
final smac = hex2bytes("6387ba65479cb7eb9df97bd48ac33159");
final srmac = hex2bytes("41677fb6398459199f1e569760df91c1");

void main() async {
  final openssl = await createOpenSSL();
  SCP03CryptoInterface crypto = SCP03Crypto(openssl);
  final cla = 0x84;
  group("scp03::off-card", () {
    test("generateCommand 1", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final data = [0x5F, 0x5F, 0x0];
      final capdu = CAPDU(cla: cla, ins: 0xD4, p1: 0x10, p2: 0x00, data: data);
      final eapdu = scp03.generateCommand(capdu);
      expect(scp03.counter, 1);
      expect(scp03.macChainingValue, isNot(Uint8List(Scp03.blockSize)));
      expect(eapdu.data.length, 16 + 8);
    });

    test("generateCommand 2", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);

      final capdu = CAPDU(
          cla: cla, ins: 0xD4, p1: 0x00, p2: 0x00, data: List.filled(239, 1));
      final eapdu = scp03.generateCommand(capdu);
      expect(scp03.counter, 1);
      expect(scp03.macChainingValue, isNot(Uint8List(Scp03.blockSize)));
      expect(eapdu.data.length, lessThanOrEqualTo(239 + 8 + 1));
    });

    test("generateCommand - macPlainTextModifier", () {
      final senc = hex2bytes("f0804c706ed866c2ae6394155336fa89");
      final smac = hex2bytes("d96dc9ac79a10e8905c9d3ff6ffd2cc3");
      final srmac = hex2bytes("fa2efe27e1351e7cd2402d12f1b262db");
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final (cipheredData, cmac) = scp03.generateCommandPayload(
        [0x01, 0x02, 0x03, 0x04],
        (cipheredData) => cipheredData,
      );
      expect(scp03.counter, 1);
      expect(scp03.macChainingValue, isNot(Uint8List(Scp03.blockSize)));
      expect(cipheredData.length, 16);
      expect(cmac.length, 8);
      expect(cmac, hex2bytes("06f279048ca232f9"));
      expect(cmac, scp03.macChainingValue.sublist(0, 8));
    });

    test("generateCommand - empty data: integrity only", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final capdu = CAPDU(cla: cla, ins: 0x00, p1: 0x00, p2: 0x00, data: []);
      final eapdu = scp03.generateCommand(capdu);
      expect(eapdu.lc, 0x08);
      expect(eapdu.le, 0x00);
      expect(eapdu.data.length, 8);
    });
  });
  group("scp03::on-card", () {
    test("generateResponse 1", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final rapdu = RAPDU(data: [0x01], sw1: 0x90, sw2: 0x00);
      final macChainingValue = [
        // Mock MAC chaining value
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
      ];
      final erapdu = scp03.generateResponse(rapdu, macChainingValue);

      expect(erapdu.data.length, 16 + 8);
      expect(erapdu.sw1, rapdu.sw1);
      expect(erapdu.sw2, rapdu.sw2);

      expect(scp03.counter, 0);
      expect(scp03.macChainingValue, macChainingValue);

      final ok = scp03.checkResponse(erapdu);
      expect(ok, isTrue);
      expect(scp03.counter, 0);

      final data = scp03.decryptResponseData(erapdu);
      expect(scp03.counter, 0);
      expect(data.length, rapdu.data.length);
      expect(memEquals(data, Uint8List.fromList(rapdu.data)), isTrue);
    });

    test("generateResponse 2", () {
      final senc = hex2bytes("A9DDAD7CD6D95B78C2E6AADDFAAC4AC8");
      final smac = hex2bytes("E7EC0D35840422F82936AC539C56A579");
      final srmac = hex2bytes("310B1300C81F42261FB29C49F9DCE181");

      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final rapdu = RAPDU(
          data: hex2bytes("97AA718D7E2B8324DA972C97BFC5DC5D34B8422527EB5FF8"),
          sw1: 0x90,
          sw2: 0x00);
      final macChainingValue = [
        // Mock MAC chaining value
        0x55, 0xB6, 0x25, 0x62, 0xC7, 0x36, 0x9E, 0x25, 0x7F, 0xF3, 0xD1, 0xFA,
        0x5E, 0xD3, 0x38, 0x67
      ];
      // To update the mac chaining value
      final _ = scp03.generateResponse(rapdu, macChainingValue);
      // Update the counter value to the expected one
      scp03.counter = 13;

      final ok = scp03.checkResponse(rapdu);
      expect(ok, isTrue);

      final data = scp03.decryptResponseData(rapdu);
      final tlv = TLVParser.parse(data)[0];
      expect(tlv.tag, [0xD3]);
      expect(tlv.value.length, 0x0D);
    });

    test("generateResponse - check the padding chomp", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final rapdu = RAPDU(
        data: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0],
        sw1: 0x90,
        sw2: 0x00,
      );
      final macChainingValue = [
        // Mock MAC chaining value
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
      ];
      final erapdu = scp03.generateResponse(rapdu, macChainingValue);

      expect(erapdu.data.length, 16 + 8);
      expect(erapdu.sw1, rapdu.sw1);
      expect(erapdu.sw2, rapdu.sw2);
      expect(scp03.counter, 0);
      expect(scp03.macChainingValue, macChainingValue);

      final ok = scp03.checkResponse(erapdu);
      expect(ok, isTrue);
      expect(scp03.counter, 0);

      final data = scp03.decryptResponseData(erapdu);
      expect(scp03.counter, 0);
      expect(data.length, rapdu.data.length);
      expect(listEquals(data, rapdu.data), isTrue);
    });

    test("generateResponse - empty data: integrity only", () {
      final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);
      final rapdu = RAPDU(data: [], sw1: 0x90, sw2: 0x00);
      final macChainingValue = List.filled(16, 0);
      final erapdu = scp03.generateResponse(rapdu, macChainingValue);

      expect(scp03.counter, 0);
      expect(erapdu.data.length, 8);
      expect(erapdu.sw1, rapdu.sw1);
      expect(erapdu.sw2, rapdu.sw2);

      final ok = scp03.checkResponse(erapdu);
      expect(ok, isTrue);
      expect(scp03.counter, 0);
    });
  });
}
