import "dart:developer";
import "dart:typed_data";

import "apdu/capdu.dart";
import "apdu/ext.dart";
import "apdu/rapdu.dart";

abstract interface class SCP03CryptoInterface {
  Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List cmacAes128(Uint8List key, Uint8List data);
}

class Scp03 {
  // Constants
  static const blockSize = 16;
  static const _zeroVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  final SCP03CryptoInterface crypto;
  final Uint8List senc;
  final Uint8List smac;
  final Uint8List srmac;

  int counter = 0x00;
  Uint8List macChainingValue;

  Scp03({
    required this.crypto,
    required List<int> senc,
    required List<int> smac,
    required List<int> srmac,
    List<int> initialMacChainingValue = _zeroVector,
  })  : senc = Uint8List.fromList(senc),
        smac = Uint8List.fromList(smac),
        srmac = Uint8List.fromList(srmac),
        macChainingValue = Uint8List.fromList(initialMacChainingValue) {
    assert(senc.length == blockSize);
    assert(smac.length == blockSize);
    assert(srmac.length == blockSize);
    assert(initialMacChainingValue.length == blockSize);
  }

  CAPDU generateCommand(CAPDU apdu) {
    counter++;

    final plainText = Uint8List.fromList(apdu.data);

    var chiperedData = Uint8List(0);
    if (plainText.isNotEmpty) {
      final icv = commandICV();
      final paddedData = _padData(plainText);
      chiperedData = crypto.aes128CbcEncrypt(
        senc,
        icv,
        paddedData,
      );
    }

    // Update MAC chaining value
    final lcc = chiperedData.length + 8;
    macChainingValue = crypto.cmacAes128(
      smac,
      Uint8List.fromList([
        ...macChainingValue,
        apdu.cla,
        apdu.ins,
        apdu.p1,
        apdu.p2,
        lcc,
        ...chiperedData,
      ]),
    );

    final cmac = macChainingValue.sublist(0, 8);

    return CAPDU(
      cla: apdu.cla,
      ins: apdu.ins,
      p1: apdu.p1,
      p2: apdu.p2,
      data: chiperedData + cmac,
    );
  }

  bool checkResponse(RAPDU rapdu) {
    final data = rapdu.data;
    if (data.length < 8) {
      return false;
    }
    final rdf = Uint8List.fromList(data.sublist(0, data.length - 8));
    final rmac = Uint8List.fromList(data.sublist(data.length - 8));
    log("Chipered Response data field: ${rdf.toHexString()}");
    log("MAC chaining value: ${macChainingValue.toHexString()}");
    final expected = crypto
        .cmacAes128(
          srmac,
          Uint8List.fromList([
            ...macChainingValue,
            ...rdf,
            rapdu.sw1,
            rapdu.sw2,
          ]),
        )
        .sublist(0, 8);
    log("rmac: ${rmac.toHexString()}, expected: ${expected.toHexString()}");
    return listEquals(rmac, expected);
  }

  Uint8List decryptResponseData(RAPDU rapdu) {
    final data = rapdu.data;
    final cipheredData = rapdu.data.sublist(0, data.length - 8);
    final icv = responeICV();
    log("ICV: ${icv.toHexString()}");
    if (cipheredData.isEmpty) {
      // R-MAC only
      return Uint8List(0);
    }
    Uint8List plainData = crypto.aes128CbcDecrypt(
      senc,
      icv,
      Uint8List.fromList(cipheredData),
    );
    log("Plain data: ${plainData.toHexString()}");
    final index = plainData.lastIndexOf(0x80);
    if (index < 0) {
      throw Exception("Invalid response data");
    }
    plainData = plainData.sublist(0, index);
    return plainData;
  }

  RAPDU generateResponse(RAPDU rapdu, List<int> macChainingValue) {
    this.macChainingValue = Uint8List.fromList(macChainingValue);

    counter++;

    final plainText = Uint8List.fromList(rapdu.data);

    var chiperedData = Uint8List(0);
    if (plainText.isNotEmpty) {
      final icv = responeICV();
      log("ICV: ${icv.toHexString()}");
      final paddedData = _padData(plainText);
      chiperedData = crypto.aes128CbcEncrypt(
        senc,
        icv,
        paddedData,
      );
    }

    // Update MAC chaining value
    final rmac = crypto
        .cmacAes128(
          srmac,
          Uint8List.fromList([
            ...macChainingValue,
            ...chiperedData,
            rapdu.sw1,
            rapdu.sw2,
          ]),
        )
        .sublist(0, 8);

    return RAPDU(
      data: [...chiperedData, ...rmac],
      sw1: rapdu.sw1,
      sw2: rapdu.sw2,
    );
  }

  Uint8List commandICV() {
    final counterBlock = Uint8List.fromList([
      ...List.filled(blockSize - 1, 0),
      counter,
    ]);
    return crypto.aes128CbcEncrypt(
      senc,
      Uint8List.fromList(_zeroVector),
      counterBlock,
    );
  }

  Uint8List responeICV() {
    final counterBlock = Uint8List.fromList([
      0x80,
      ...List.filled(blockSize - 2, 0),
      counter,
    ]);
    return crypto.aes128CbcEncrypt(
      senc,
      Uint8List.fromList(_zeroVector),
      counterBlock,
    );
  }

  static Uint8List _padData(Uint8List payload) {
    final res = [...payload, 0x80];
    final padding = (blockSize - res.length % blockSize) % blockSize;
    return Uint8List.fromList(
        [...res, if (padding > 0) ...List.filled(padding, 0)]);
  }
}
