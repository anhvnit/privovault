import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// AES-256-GCM with a fresh 96-bit random nonce per message.
/// Wire format: nonce(12) || ciphertext || tag(16).
///
/// `FlutterCryptography.enable()` (called in main) swaps in CryptoKit /
/// javax.crypto implementations, so large buffers stay fast.
abstract final class Aead {
  static final AesGcm _alg = AesGcm.with256bits();
  static const nonceLength = 12;
  static const tagLength = 16;

  static Future<Uint8List> seal(Uint8List key, List<int> plaintext, {List<int> aad = const []}) async {
    _checkKey(key);
    final box = await _alg.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: randomBytes(nonceLength),
      aad: aad,
    );
    return Uint8List.fromList(box.concatenation());
  }

  /// Throws [SecretBoxAuthenticationError] if the data or AAD was tampered with
  /// or the key is wrong. Never returns unauthenticated plaintext.
  static Future<Uint8List> open(Uint8List key, List<int> sealed, {List<int> aad = const []}) async {
    _checkKey(key);
    if (sealed.length < nonceLength + tagLength) throw const FormatException('Sealed blob too short');
    final box = SecretBox.fromConcatenation(sealed, nonceLength: nonceLength, macLength: tagLength);
    final clear = await _alg.decrypt(box, secretKey: SecretKey(key), aad: aad);
    return Uint8List.fromList(clear);
  }

  static void _checkKey(Uint8List key) {
    if (key.length != 32) throw ArgumentError('AES-256 key must be 32 bytes');
    // Keys are zeroed on lock (see [wipe]). A sync or save still in flight
    // when the vault locks must fail, never encrypt under a known key.
    if (isWipedKey(key)) throw StateError('Key material was wiped (vault locked)');
  }
}

/// True when every byte is zero: a key that was [wipe]d. A real 256-bit
/// key from a CSPRNG / HKDF is all-zero with probability 2^-256.
bool isWipedKey(List<int> key) {
  var acc = 0;
  for (final x in key) {
    acc |= x;
  }
  return acc == 0;
}

final Random _rng = Random.secure();

Uint8List randomBytes(int n) => Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

/// Best-effort zeroisation of key material held in Dart memory.
///
/// Never throws: buffers that arrive read-only (platform-channel messages,
/// views over immutable data) are skipped. Callers must not let key cleanup
/// mask the real outcome — this runs in `finally` blocks.
void wipe(Uint8List? b) {
  if (b == null) return;
  try {
    b.fillRange(0, b.length, 0);
  } on UnsupportedError {
    // Unmodifiable view — nothing we can zero; drop the reference instead.
  }
}

/// Constant-time comparison.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) {
    r |= a[i] ^ b[i];
  }
  return r == 0;
}

Future<Uint8List> sha256(List<int> data) async =>
    Uint8List.fromList((await Sha256().hash(data)).bytes);
