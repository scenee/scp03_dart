import "dart:developer";
import "dart:typed_data";

import "package:ffi_assist/ffi_assist.dart";

import "apdu/capdu.dart";
import "apdu/rapdu.dart";

/// An interface for SCP03 cryptographic operations.
///
/// This interface defines the necessary methods and properties that any
/// SCP03 cryptographic implementation must provide. SCP03 is a secure
/// channel protocol used for establishing a secure communication channel
/// between a off-card(host) entity and a on-card entity.
///
/// Implementations of this interface should provide the cryptographic
/// operations required for SCP03, such as key derivation, encryption,
/// and MAC generation.
abstract interface class SCP03CryptoInterface {
  Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List data);
  Uint8List cmacAes128(Uint8List key, Uint8List data);
}

/// A class representing the SCP03 protocol.
///
/// SCP03 (Secure Channel Protocol 03) is a protocol used for establishing
/// a secure channel between on-card and off-card entities. This class provides
/// methods and properties to facilitate the secure communication.
///
/// Note: Ensure that you have to generate necessary cryptographic keys using
/// certain key derivation methods before using this class.
class Scp03 {
  // Constants
  static const blockSize = 16;
  static const _zeroVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  final SCP03CryptoInterface crypto;

  /// The S-ENC key
  final Uint8List senc;
  // The S-MAC key
  final Uint8List smac;
  // The S-RMAC key
  final Uint8List srmac;

  /// Generally the counter is incremented for each command generataion in a
  /// session using SCP03. The counter is used to generate the ICV (Initial
  /// Chaining Value) for the command and response. An on-card entity should
  /// increment the counter manually for each response to a command.
  int counter = 0x00;

  Uint8List _macChainingValue;

  /// The current MAC chaining value used for the C-MAC and R-MAC generation.
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

  /// Returns a secure [CAPDU] object including an encrypted data and the C-MAC
  /// from the given [apdu] object.
  ///
  /// The counter for ICV is incremented for each method call.
  CAPDU generateCommand(CAPDU apdu) {
    final (cipheredData, cmac) = generateCommandPayload(
      apdu.data,
      (cipheredData) {
        final lcc = cipheredData.length + 8;
        return Uint8List.fromList(
            [apdu.cla, apdu.ins, apdu.p1, apdu.p2, lcc, ...cipheredData]);
      },
    );
    return CAPDU(
      cla: apdu.cla,
      ins: apdu.ins,
      p1: apdu.p1,
      p2: apdu.p2,
      data: [...cipheredData, ...cmac],
    );
  }

  /// Returns an encrypted payload data and the C-MAC for the given [data].
  ///
  /// If you want to modify the plaintext data for the MAC chaining value
  /// calculation, you can provide a [macPlainTextModifier] function. This
  /// function should return the modified plaintext data for the MAC calculation.
  /// By default, the MAC is calculated with the C-APDU header and the encrypted
  /// payload data.
  ///
  /// The counter for ICV is incremented for each method call.
  (Uint8List cipheredData, Uint8List cmac) generateCommandPayload(
    List<int> data,
    Uint8List Function(Uint8List cipheredData) macPlainTextModifier,
  ) {
    counter++;

    final plainText = Uint8List.fromList(data);
    final cipheredData = _encryptPayload(plainText);

    // Update MAC chaining value
    final Uint8List macInputText =
        Uint8List.fromList(macPlainTextModifier(cipheredData));

    _macChainingValue = crypto.cmacAes128(
      smac,
      Uint8List.fromList([
        ..._macChainingValue,
        ...macInputText,
      ]),
    );
    final cmac = _macChainingValue.sublist(0, 8);
    return (cipheredData, cmac);
  }

  /// Encrypts the payload data using AES-128 CBC encryption.
  ///
  /// The payload is padded using 4.1.4 AES Padding. Somtimes the cmac doesn't
  /// contains the C-APDU header and Lc field. That's why this method is. You
  /// can use this with [updateMacChainingValue] and [cmac] methods to generate
  /// the SCP03 command payload and cmac as below:
  Uint8List _encryptPayload(Uint8List payload) {
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

  /// Checks the response RAPDU by verifying the MAC.
  ///
  /// If the [withSW] is false, the SW1 and SW2 bytes are not included to
  /// calculate the R-MAC.
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
  /// The MAC chaining value is updated with the given [macChainingValue].
  /// Before calling this method, you may need to increment the counter.
  /// The R-MAC is calculated with the R-APDU header and the encrypted payload data.
  RAPDU generateResponse(RAPDU rapdu, List<int> macChainingValue) {
    _macChainingValue = Uint8List.fromList(macChainingValue);

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
