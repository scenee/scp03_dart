# scp03

A SCP03 (GlobalPlatform Technology Secure Channel Protocol '03') implementation in Dart.

This implementation conforms to "GlobalPlatform Card Technology Secure Channel Protocol '03' Card Specification v2.2 – Amendment D Version 1.1.1" (GPC_SPE_014).

## Features

- Secure communication using SCP03 protocol
- APDU command and response handling
- TLV (Tag-Length-Value) encoding and decoding

## Limitations

- Only AES-128 is supported. AES-192 and AES-256 are not supported.
- This library won't support "Explicit Secure Channel Initiation".

## Installation

Add the following to your `pubspec.yaml` file:

```yaml
dependencies:
  scp03: ^1.0.0
```

Then run:

```sh
dart pub get
```

## Usage

```dart
import 'package:scp03/scp03.dart';

void main() {
  final senc = Uint8List.fromList([...]);
  final smac = Uint8List.fromList([...]);
  final srmac = Uint8List.fromList([...]);

  // Initialize SCP03 with OpenSSL
  final openssl = await createOpenSSL();
  SCP03CryptoInterface crypto = SCP03Crypto(openssl);
  final scp03 = Scp03(crypto: crypto, senc: senc, smac: smac, srmac: srmac);

  // A plain CAPDU command
  final capdu = CAPDU(cla: 0x84, ins: 0xD4, p1: 0x10, p2: 0x00, data: [0x5F, 0x5F, 0x0]);

  // Generate the CAPDU command using SCP03
  final apdu = scp03.generateCommand(capdu);
}
```

## Testing

Before running the tests, just install the OpenSSL v3 as below.

Debian, Ubuntu:

```sh
sudo apt-get install libssl-dev
```

macOS:

```sh
brew install openssl@3 # Homebrew
```

See also verify the installation paths and `getLibraryPath()` implementation in [scp03_crypto.dart](test/crypto/scp03_crypto.dart).

To run the tests, use the following command:

```sh
dart test
```

## License

This project is licensed under the MIT License.
