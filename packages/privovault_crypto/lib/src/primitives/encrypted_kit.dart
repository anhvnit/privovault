import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'aead.dart';
import 'recovery.dart';

/// Password-protected recovery kit for storage as a FILE.
///
/// A printed kit may carry the 12 words in clear text (paper lives outside
/// the phone). A file does not: a PDF in the Files app of a lost phone would
/// bypass Face ID entirely. The file therefore carries only
///
///   "qlv-ekit:1:" + base64url( version(1) | salt(16) | nonce(12) | ciphertext | tag(16) )
///
/// where the key is Argon2id(password, salt) and the plaintext is
/// {"p": <12 words>, "v": <vaultId>}. Without the kit password the file is
/// useless — even stored next to the vault in the same cloud account.
abstract final class EncryptedRecoveryKit {
  static const prefix = 'qlv-ekit:1:';
  static const _version = 1;
  static const minPasswordLength = 12;

  /// Upper bound on an encrypted kit code accepted by [open].
  static const maxKitLength = 2048;

  /// Argon2id, above the OWASP baseline (m=19 MiB, t=2, p=1): 32 MiB, t=3.
  /// About a second on a phone (release build) — paid once by the owner,
  /// and per guess by an attacker. Parameters are fixed by the kit version.
  static Argon2id _kdf() => Argon2id(parallelism: 1, memory: 32768, iterations: 3, hashLength: 32);

  static List<int> get _aad => utf8.encode('qlv-ekit|v1');

  /// Encrypt [phrase] under [password]. Throws [ArgumentError] if the
  /// password is too short or the phrase is invalid.
  static Future<String> seal({required String phrase, required String vaultId, required String password}) async {
    if (password.length < minPasswordLength) throw ArgumentError('Kit password too short');
    final normalized = RecoveryPhrase.normalize(phrase);
    if (!RecoveryPhrase.isValid(normalized)) throw ArgumentError('Invalid recovery phrase');
    final salt = randomBytes(16);
    final key = await _deriveKey(password, salt);
    try {
      final sealed = await Aead.seal(key, utf8.encode(jsonEncode({'p': normalized, 'v': vaultId})), aad: _aad);
      final blob = Uint8List.fromList([_version, ...salt, ...sealed]);
      return prefix + base64Url.encode(blob).replaceAll('=', '');
    } finally {
      wipe(key);
    }
  }

  static bool looksLikeKit(String text) => text.trim().startsWith(prefix);

  /// Decrypt a kit. Returns the phrase and the vault id it belongs to.
  /// Throws [FormatException] for malformed input and
  /// [SecretBoxAuthenticationError] for a wrong password / tampered kit.
  static Future<({String phrase, String vaultId})> open(String kit, String password) async {
    final t = kit.trim();
    if (!t.startsWith(prefix)) throw const FormatException('Not an encrypted PrivoVault kit');
    // A real kit is ~250 characters; refuse pasted / scanned junk before
    // decoding it (the Argon2 cost is fixed by the version, never read
    // from the kit).
    if (t.length > maxKitLength) throw const FormatException('Kit code too long');
    var b = t.substring(prefix.length);
    b += '=' * ((4 - b.length % 4) % 4);
    final blob = base64Url.decode(b);
    if (blob.length < 1 + 16 + Aead.nonceLength + Aead.tagLength || blob[0] != _version) {
      throw const FormatException('Unsupported kit version');
    }
    final salt = blob.sublist(1, 17);
    final key = await _deriveKey(password, salt);
    try {
      final clear = await Aead.open(key, blob.sublist(17), aad: _aad);
      final j = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
      wipe(clear);
      return (phrase: j['p'] as String, vaultId: j['v'] as String);
    } finally {
      wipe(key);
    }
  }

  static Future<Uint8List> _deriveKey(String password, List<int> salt) async {
    final k = await _kdf().deriveKey(secretKey: SecretKey(utf8.encode(password)), nonce: salt);
    return Uint8List.fromList(await k.extractBytes());
  }
}
