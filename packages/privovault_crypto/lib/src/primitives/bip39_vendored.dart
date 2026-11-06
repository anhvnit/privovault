import 'dart:typed_data';

import 'package:cryptography/dart.dart';

import 'aead.dart' show randomBytes;
import 'bip39_wordlist_en.dart';

/// Vendored BIP-39 (English) — replaces the unmaintained `bip39` package.
///
/// Byte-for-byte the same encoding as `bip39` 1.0.6 for the calls the app
/// uses (generate / validate / mnemonic → entropy), so existing phrases keep
/// unlocking. Rules mirrored from that package:
/// - words are split on a single ' ' with no trimming (callers normalise);
/// - word count must be a multiple of 3, entropy 16..32 bytes and a multiple
///   of 4 (12/15/18/21/24 words), checksum = first ENT/32 bits of SHA-256.
/// One deliberate difference: `bip39` drew entropy with `nextInt(255)` (bytes
/// were never 0xFF); we use the full byte range. That changes only which
/// phrases can be generated, never how a phrase decodes.
/// Seed derivation (mnemonicToSeed) is not vendored: the app never uses it.
abstract final class Bip39 {
  static final Map<String, int> _index = <String, int>{
    for (var i = 0; i < bip39English.length; i++) bip39English[i]: i,
  };

  static bool _validEntropyLength(int n) => n >= 16 && n <= 32 && n % 4 == 0;

  /// Synchronous SHA-256 (pure Dart; inputs here are at most 32 bytes).
  static List<int> _sha256(List<int> data) => DartSha256().hashSync(data).bytes;

  /// [strengthBits] 128 → 12 words, 256 → 24 words.
  static String generateMnemonic({int strengthBits = 128}) {
    if (strengthBits % 32 != 0 || !_validEntropyLength(strengthBits ~/ 8)) {
      throw ArgumentError.value(strengthBits, 'strengthBits');
    }
    final entropy = randomBytes(strengthBits ~/ 8);
    try {
      return entropyToMnemonic(entropy);
    } finally {
      entropy.fillRange(0, entropy.length, 0);
    }
  }

  static String entropyToMnemonic(List<int> entropy) {
    final n = entropy.length;
    if (!_validEntropyLength(n)) throw ArgumentError('Invalid entropy length: $n bytes');
    final entBits = n * 8;
    final csBits = entBits ~/ 32;
    final hash = _sha256(entropy);
    int bitAt(int i) {
      if (i < entBits) return (entropy[i >> 3] >> (7 - (i & 7))) & 1;
      final j = i - entBits;
      return (hash[j >> 3] >> (7 - (j & 7))) & 1;
    }

    final words = <String>[];
    final total = entBits + csBits; // always a multiple of 11
    for (var w = 0; w < total; w += 11) {
      var idx = 0;
      for (var b = 0; b < 11; b++) {
        idx = (idx << 1) | bitAt(w + b);
      }
      words.add(bip39English[idx]);
    }
    return words.join(' ');
  }

  /// Decodes and checks the checksum. Throws [FormatException] when invalid.
  static Uint8List mnemonicToEntropy(String mnemonic) {
    final e = _decode(mnemonic);
    if (e == null) throw const FormatException('Invalid mnemonic');
    return e;
  }

  static bool validateMnemonic(String mnemonic) {
    final e = _decode(mnemonic);
    if (e == null) return false;
    e.fillRange(0, e.length, 0);
    return true;
  }

  static Uint8List? _decode(String mnemonic) {
    final words = mnemonic.split(' ');
    if (words.length % 3 != 0) return null;
    final totalBits = words.length * 11;
    final entBits = (totalBits ~/ 33) * 32;
    final csBits = totalBits - entBits;
    final n = entBits ~/ 8;
    if (!_validEntropyLength(n)) return null;

    final bits = Uint8List(totalBits); // one bit per element
    for (var w = 0; w < words.length; w++) {
      final idx = _index[words[w]];
      if (idx == null) return null;
      for (var b = 0; b < 11; b++) {
        bits[w * 11 + b] = (idx >> (10 - b)) & 1;
      }
    }

    final entropy = Uint8List(n);
    for (var i = 0; i < entBits; i++) {
      entropy[i >> 3] |= bits[i] << (7 - (i & 7));
    }
    final hash = _sha256(entropy);
    var ok = true;
    for (var j = 0; j < csBits; j++) {
      final expected = (hash[j >> 3] >> (7 - (j & 7))) & 1;
      if (bits[entBits + j] != expected) ok = false;
    }
    bits.fillRange(0, bits.length, 0);
    if (!ok) {
      entropy.fillRange(0, entropy.length, 0);
      return null;
    }
    return entropy;
  }
}
