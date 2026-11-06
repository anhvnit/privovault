import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:privovault_crypto/privovault_crypto.dart';
import 'package:privovault_crypto/src/primitives/bip39_vendored.dart';
import 'package:privovault_crypto/src/primitives/bip39_wordlist_en.dart';

Uint8List _hex(String h) =>
    Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);

String _toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// Trezor reference vectors (python-mnemonic vectors.json, "english"):
// entropy → mnemonic. Seeds are not covered: the app never derives one.
const _vectors = <(String, String)>[
  ('00000000000000000000000000000000',
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),
  ('7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow'),
  ('80808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'),
  ('ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'),
  ('9e885d952ad362caeb4efe34a8e91bd2', 'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic'),
  ('0000000000000000000000000000000000000000000000000000000000000000',
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'),
  ('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'),
  ('68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c',
      'hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel '
          'tennis maple dilemma loan word shrug inflict delay length'),
];

void main() {
  group('BIP-39 (vendored)', () {
    test('wordlist is the canonical 2048-word English list', () {
      expect(bip39English.length, 2048);
      expect(bip39English.first, 'abandon');
      expect(bip39English.last, 'zoo');
      expect(bip39English.toSet().length, 2048);
      final sorted = [...bip39English]..sort();
      expect(sorted, bip39English);
    });

    for (final (entropy, mnemonic) in _vectors) {
      test('vector ${entropy.substring(0, 8)}… (${entropy.length * 4} bits)', () {
        expect(Bip39.entropyToMnemonic(_hex(entropy)), mnemonic);
        expect(Bip39.validateMnemonic(mnemonic), isTrue);
        expect(_toHex(Bip39.mnemonicToEntropy(mnemonic)), entropy);
      });
    }

    test('rejects a bad checksum, unknown word, wrong count, double space', () {
      // last word changed: "about" → "above" breaks the checksum
      expect(Bip39.validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon above'), isFalse);
      expect(Bip39.validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon bitcoin'), isFalse);
      expect(Bip39.validateMnemonic('abandon abandon abandon'), isFalse);
      expect(Bip39.validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon about'), isFalse);
      expect(Bip39.validateMnemonic('abandon  abandon abandon abandon abandon abandon abandon abandon '
          'abandon abandon abandon about'), isFalse);
      expect(Bip39.validateMnemonic(''), isFalse);
      expect(() => Bip39.mnemonicToEntropy('zoo zoo zoo'), throwsFormatException);
    });

    test('generate → validate → entropy round trip (128 and 256 bits)', () {
      for (var i = 0; i < 50; i++) {
        final m12 = Bip39.generateMnemonic();
        expect(m12.split(' ').length, 12);
        expect(Bip39.validateMnemonic(m12), isTrue);
        expect(Bip39.entropyToMnemonic(Bip39.mnemonicToEntropy(m12)), m12);
      }
      final m24 = Bip39.generateMnemonic(strengthBits: 256);
      expect(m24.split(' ').length, 24);
      expect(Bip39.mnemonicToEntropy(m24).length, 32);
    });

    test('RecoveryPhrase accepts normalised 12-word input only', () {
      expect(
          RecoveryPhrase.isValid('  Legal winner THANK year wave sausage worth useful legal winner thank yellow '),
          isTrue);
      expect(RecoveryPhrase.isValid(_vectors[5].$2), isFalse); // 24 words
      expect(RecoveryPhrase.isValid(RecoveryPhrase.generate()), isTrue);
    });
  });
}
