import "dart:developer";
import "dart:io";
import "dart:ffi" as ffi;
import "dart:typed_data";
import "package:ffi/ffi.dart";
import "package:scp03/scp03.dart";
import "package:scp03/src/apdu/ext.dart";

import "openssl.dart";

String getOpensslLibraryPath() {
  final String libraryPath;
  if (Platform.isLinux) {
    libraryPath = "/usr/lib/aarch64-linux-gnu/libcrypto.so"; // For Linux
  } else if (Platform.isMacOS) {
    libraryPath =
        "/opt/local/libexec/openssl3/lib/libcrypto.3.dylib"; // For Mac
  } else {
    throw UnsupportedError("Unsupported platform");
  }
  return libraryPath;
}

OpenSSL createOpenSSL() {
  final dylib = ffi.DynamicLibrary.open(getOpensslLibraryPath());
  return OpenSSL(dylib);
}

class SCP03Crypto implements SCP03CryptoInterface {
  final OpenSSL openssl;
  SCP03Crypto(this.openssl);
  @override
  Uint8List aes128CbcEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List inData,
  ) {
    log("key: ${key.toHexString()} iv: ${iv.toHexString()} inData: ${inData.toHexString()}");
    return using((arena) {
      final ctx = openssl.EVP_CIPHER_CTX_new();

      if (ctx == ffi.nullptr) {
        throw Exception("openssl.EVP_CIPHER_CTX_new failed");
      }
      final keyPtr = key.toPointer(allocator: arena);
      final ivPtr = iv.toPointer(allocator: arena);
      if (openssl.EVP_EncryptInit_ex(
              ctx, openssl.EVP_aes_128_cbc(), ffi.nullptr, keyPtr, ivPtr) !=
          1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("openssl.EVP_EncryptInit failed");
      }

      // Disable padding
      openssl.EVP_CIPHER_CTX_set_padding(ctx, 0);

      int outlen = 0;
      final bufferSize = 255;
      final inlen = inData.length;
      final inDataPtr = inData.toPointer(allocator: arena);

      final outlPtr = arena<ffi.Int>(1);
      final outPtr = arena<ffi.UnsignedChar>(bufferSize);
      if (openssl.EVP_EncryptUpdate(ctx, outPtr, outlPtr, inDataPtr, inlen) !=
          1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("openssl.EVP_EncryptUpdate failed");
      }
      outlen = outlPtr.value;

      if (openssl.EVP_EncryptFinal(ctx, outPtr + outlen, outlPtr) != 1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("openssl.EVP_EncryptFinal_ex failed");
      }
      outlen += outlPtr.value;
      log("outlen: $outlen");

      openssl.EVP_CIPHER_CTX_free(ctx);
      return Uint8List.fromList(outPtr.cast<ffi.Uint8>().asTypedList(outlen));
    });
  }

  @override
  Uint8List aes128CbcDecrypt(
      Uint8List key, Uint8List iv, Uint8List cipheredData) {
    return using((arena) {
      final ctx = openssl.EVP_CIPHER_CTX_new();
      if (ctx == ffi.nullptr) {
        throw Exception("EVP_CIPHER_CTX_new failed");
      }

      final keyPtr = key.toPointer(allocator: arena);
      final ivPtr = iv.toPointer(allocator: arena);
      if (openssl.EVP_DecryptInit(
              ctx, openssl.EVP_aes_128_cbc(), keyPtr, ivPtr) !=
          1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("EVP_DecryptInit failed");
      }

      // Disable padding
      openssl.EVP_CIPHER_CTX_set_padding(ctx, 0);

      int outlen = 0;
      final bufferSize = 255;
      final inlen = cipheredData.length;
      final inDataPtr = cipheredData.toPointer(allocator: arena);

      final outPtr = arena<ffi.UnsignedChar>(bufferSize);
      final outlPtr = arena<ffi.Int>(1);
      if (openssl.EVP_DecryptUpdate(ctx, outPtr, outlPtr, inDataPtr, inlen) !=
          1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("EVP_DecryptUpdate failed");
      }

      outlen = outlPtr.value;

      if (openssl.EVP_DecryptFinal(ctx, outPtr + outlen, outlPtr) != 1) {
        openssl.EVP_CIPHER_CTX_free(ctx);
        throw Exception("EVP_DecryptFinal failed");
      }
      outlen += outlPtr.value;

      openssl.EVP_CIPHER_CTX_free(ctx);

      return Uint8List.fromList(outPtr.cast<ffi.Uint8>().asTypedList(outlen));
    });
  }

  @override
  Uint8List cmacAes128(Uint8List key, Uint8List data) {
    return using((arena) {
      final keyPtr = key.toPointer(allocator: arena);
      final keylen = key.length;
      final dataPtr = data.toPointer(allocator: arena);
      final datalen = data.length;

      final mac = openssl.EVP_MAC_fetch(ffi.nullptr,
          OSSL_MAC_NAME_CMAC.toPointer(allocator: arena), ffi.nullptr);
      final mctx = openssl.EVP_MAC_CTX_new(mac);

      final params = arena<OSSL_PARAM>(2);
      params[0] = openssl.OSSL_PARAM_construct_utf8_string(
          OSSL_MAC_PARAM_CIPHER.toPointer(allocator: arena),
          SN_aes_128_cbc.toPointer(allocator: arena),
          11);
      params[1] = openssl.OSSL_PARAM_construct_end();

      openssl.EVP_MAC_init(mctx, keyPtr.cast(), keylen, params);
      openssl.EVP_MAC_update(mctx, dataPtr, datalen);

      final cmacPtr = arena<ffi.UnsignedChar>(16);
      final cmacSize = arena<ffi.Size>(1);

      openssl.EVP_MAC_final(mctx, cmacPtr, cmacSize, 16);

      assert(cmacSize.value == 16);

      openssl.EVP_MAC_CTX_free(mctx);
      return Uint8List.fromList(cmacPtr.cast<ffi.Uint8>().asTypedList(16));
    });
  }
}

extension Uint8ListPointer on Uint8List {
  ffi.Pointer<ffi.UnsignedChar> toPointer({ffi.Allocator allocator = calloc}) {
    final p = allocator<ffi.UnsignedChar>(length);
    for (var i = 0; i < length; i++) {
      p[i] = this[i];
    }
    return p;
  }
}

extension StringPointer on String {
  ffi.Pointer<T> toPointer<T extends ffi.NativeType>(
      {ffi.Allocator allocator = calloc}) {
    final p = allocator<ffi.UnsignedChar>(length);
    for (var i = 0; i < codeUnits.length; i++) {
      p[i] = codeUnits[i];
    }
    return p.cast<T>();
  }
}
