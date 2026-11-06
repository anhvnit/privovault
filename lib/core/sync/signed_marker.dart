import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Small owner-signed control files in the cloud folder: the vault anchor
/// (`ql.anchor.<vaultId>`) and the "moved" marker (`privovault.moved`).
///
/// ```
/// { "v": 2,
///   "payload": b64(JSON {kind, vault_id, at, ...}),
///   "sig": b64(Ed25519_owner("qlv-marker|" ‖ payload)),
///   ...legacy plaintext fields (e.g. "to") for older app versions }
/// ```
/// Signed with the same owner Ed25519 key as QLV1 packages and the key-ring
/// (`OwnerMeta.ownerSigningSeed`; staff verify with
/// `StaffCredentials.ownerSigningKey`). The context prefix keeps marker
/// signatures from ever being valid for another message type.
abstract final class SignedMarker {
  static const _context = 'qlv-marker|';

  /// `kind` of the notice an owner signs with its REPLACED signing key when
  /// a new Emergency Kit rotates the owner identity (attached to key-rings;
  /// see `OwnerMeta.ownerIdentityNotices`).
  static const kindOwnerIdentityRotated = 'owner-identity-rotated';

  static List<int> _message(List<int> payload) => [...utf8.encode(_context), ...payload];

  /// Builds a signed marker. [legacy] fields are copied in plaintext at the
  /// top level for older readers; they are never trusted by [verify].
  static Future<Uint8List> build(
    Map<String, Object?> payload,
    Uint8List ownerSigningSeed, {
    Map<String, Object?> legacy = const {},
  }) async {
    final p = utf8.encode(jsonEncode(payload));
    final kp = await Ed25519().newKeyPairFromSeed(ownerSigningSeed);
    final sig = await Ed25519().sign(_message(p), keyPair: kp);
    return Uint8List.fromList(utf8.encode(jsonEncode({
      ...legacy,
      'v': 2,
      'payload': base64Encode(p),
      'sig': base64Encode(sig.bytes),
    })));
  }

  /// The signed payload, or null when the file is unsigned (legacy),
  /// malformed, or not signed by [ownerSigningKey]. Never throws.
  static Future<Map<String, dynamic>?> verify(Uint8List file, List<int> ownerSigningKey) async {
    try {
      if (ownerSigningKey.length != 32) return null;
      final j = jsonDecode(utf8.decode(file));
      if (j is! Map || j['v'] != 2 || j['payload'] is! String || j['sig'] is! String) return null;
      final payload = base64Decode(j['payload'] as String);
      final sig = base64Decode(j['sig'] as String);
      if (sig.length != 64) return null;
      final ok = await Ed25519().verify(
        _message(payload),
        signature: Signature(sig, publicKey: SimplePublicKey(ownerSigningKey, type: KeyPairType.ed25519)),
      );
      if (!ok) return null;
      final p = jsonDecode(utf8.decode(payload));
      return p is Map<String, dynamic> ? p : null;
    } catch (_) {
      return null;
    }
  }

  /// True when [file] claims to be a signed marker (whether or not the
  /// signature is valid) — distinguishes forged from legacy unsigned files.
  static bool looksSigned(Uint8List file) {
    try {
      final j = jsonDecode(utf8.decode(file));
      return j is Map && j['v'] == 2 && j.containsKey('sig');
    } catch (_) {
      return false;
    }
  }

  /// Ed25519 public key for an owner signing seed.
  static Future<List<int>> publicKeyFromSeed(Uint8List seed) async {
    final kp = await Ed25519().newKeyPairFromSeed(seed);
    return (await kp.extractPublicKey()).bytes;
  }
}
