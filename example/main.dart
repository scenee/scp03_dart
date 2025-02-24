import "package:ffi_assist/ffi_assist.dart";
import "package:scp03/scp03.dart";
import "../test/crypto/scp03_crypto.dart";

void main() async {
  final senc = hex2bytes("161886cb9ae7403d8dbccfe36b8a0426");
  final smac = hex2bytes("6387ba65479cb7eb9df97bd48ac33159");
  final srmac = hex2bytes("41677fb6398459199f1e569760df91c1");

  final openssl = await createOpenSSL();
  SCP03CryptoInterface crypto = SCP03Crypto(openssl);
  final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);

  final data = [0x5F, 0x5F, 0x0];
  final capdu = CAPDU(cla: 0x84, ins: 0xD4, p1: 0x10, p2: 0x00, data: data);
  final eapdu = scp03.generateCommand(capdu);
  print("APDU: ${eapdu.toString()}");
}
