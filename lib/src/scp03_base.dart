import "dart:developer";
import "dart:typed_data";

import "package:ffi_assist/ffi_assist.dart";

import "apdu/capdu.dart";
import "apdu/rapdu.dart";

abstract interface class SCP03CryptoInterface {
  Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List cmacAes128(Uint8List key, Uint8List data);
}

/// A class that implements the SCP03 (Secure Channel Protocol '03')
/// for secure communication using AES-128 encryption.
class Scp03 {
  // Constants
  static const blockSize = 16;
  static const _zeroVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  final SCP03CryptoInterface crypto;
  final Uint8List senc;
  final Uint8List smac;
  final Uint8List srmac;

  int counter = 0x00;

  Uint8List _macChainingValue;
  Uint8List get macChainingValue => _macChainingValue;

  /// Creates an instance of [Scp03] with the given encryption keys and crypto interface.
  Scp03({
    required this.crypto,
    required List<int> senc,
    required List<int> smac,
    required List<int> srmac,
    List<int> initialMacChainingValue = _zeroVector,
  })  : senc = Uint8List.fromList(senc),
        smac = Uint8List.fromList(smac),
        srmac = Uint8List.fromList(srmac),
        _macChainingValue = Uint8List.fromList(initialMacChainingValue) {
    assert(senc.length == blockSize);
    assert(smac.length == blockSize);
    assert(srmac.length == blockSize);
    assert(initialMacChainingValue.length == blockSize);
  }

  /// Generates a secure CAPDU command by encrypting the data and adding a C-MAC.
  ///
  /// The counter for ICV is incremented for each command. The C-MAC is calculated
  /// with the C-APDU header and the encrypted payload data. The MAC chaining value
  /// is updated with the C-APDU header and the encrypted payload data.
  CAPDU generateCommand(CAPDU apdu) {
    counter++;

    final plainText = Uint8List.fromList(apdu.data);
    final chiperedData = encryptPayload(plainText);

    // Update MAC chaining value
    final lcc = chiperedData.length + 8;
    updateMacChainingValue(Uint8List.fromList([
      apdu.cla,
      apdu.ins,
      apdu.p1,
      apdu.p2,
      lcc,
      ...chiperedData,
    ]));

    return CAPDU(
      cla: apdu.cla,
      ins: apdu.ins,
      p1: apdu.p1,
      p2: apdu.p2,
      data: chiperedData + cmac(),
    );
  }

  /// Encrypts the payload data using AES-128 CBC encryption.
  ///
  /// The payload is padded using 4.1.4 AES Padding. Somtimes the cmac doesn't
  /// contains the C-APDU header and Lc field. That's why this method is. You
  /// can use this with [updateMacChainingValue] and [cmac] methods to generate
  /// the SCP03 command payload and cmac as below:
  /// ```dart
  /// final cipheredData = scp03.encryptPayload(data);
  /// scp03.updateMacChainingValue(cipheredData);
  /// final cmac = scp03.cmac();
  /// final commandData = Uint8List.fromList([...cipheredData, ...cmac]);
  /// ```
  Uint8List encryptPayload(Uint8List payload) {
    var chiperedData = Uint8List(0);
    if (payload.isNotEmpty) {
      final icv = commandICV();
      final paddedData = _padData(payload);
      chiperedData = crypto.aes128CbcEncrypt(
        senc,
        icv,
        paddedData,
      );
    }
    return chiperedData;
  }

  /// Update the current MAC chaining value with the given [macInputText].
  ///
  /// This operation is used for APDU Command C-MAC generation.
  void updateMacChainingValue(Uint8List macInputText) {
    _macChainingValue = crypto.cmacAes128(
      smac,
      Uint8List.fromList([
        ..._macChainingValue,
        ...macInputText,
      ]),
    );
  }

  /// Returns the C-MAC value from the current MAC chaining value.
  Uint8List cmac() => _macChainingValue.sublist(0, 8);

  /// Checks the response RAPDU by verifying the MAC.
  bool checkResponse(RAPDU rapdu, {bool withSW = true}) {
    final data = rapdu.data;
    if (data.length < 8) {
      return false;
    }
    final rdf = Uint8List.fromList(data.sublist(0, data.length - 8));
    final rmac = Uint8List.fromList(data.sublist(data.length - 8));
    log("Chipered Response data field: ${rdf.toHexString()}");
    log("MAC chaining value: ${_macChainingValue.toHexString()}");
    final expected = crypto
        .cmacAes128(
          srmac,
          Uint8List.fromList([
            ..._macChainingValue,
            ...rdf,
            if (withSW) rapdu.sw1,
            if (withSW) rapdu.sw2,
          ]),
        )
        .sublist(0, 8);
    log("rmac: ${rmac.toHexString()}, expected: ${expected.toHexString()}");
    return memEquals(rmac, expected);
  }

  /// Decrypts the response data from the RAPDU.
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

  /// Generates a secure RAPDU response by encrypting the data and adding a R-MAC.
  ///
  /// The counter for ICV is incremented for each response. The MAC chaining
  /// value is updated with the given [macChainingValue]. The R-MAC is
  /// calculated with the R-APDU header and the encrypted payload data.
  RAPDU generateResponse(RAPDU rapdu, List<int> macChainingValue) {
    _macChainingValue = Uint8List.fromList(macChainingValue);

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

  /// Generates the ICV (Initial Chaining Value) for the command.
  ///
  /// This method doesn't increment the counter.
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

  /// Generates the ICV (Initial Chaining Value) for the response.
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

  /// Pads the data to the block size using the ISO/IEC 7816-4 padding scheme.
  static Uint8List _padData(Uint8List payload) {
    final res = [...payload, 0x80];
    final padding = (blockSize - res.length % blockSize) % blockSize;
    return Uint8List.fromList(
        [...res, if (padding > 0) ...List.filled(padding, 0)]);
  }
}
