import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/aead.dart';
import '../crypto/vault_keys.dart';
import 'signed_marker.dart';

/// The owner's identity keys changed (new Emergency Kit): the key-ring is
/// signed by a key this staff phone does not trust, but carries a notice
/// signed by the key it DOES trust. The phone must be paired again.
class OwnerIdentityRotated implements Exception {
  const OwnerIdentityRotated();
  @override
  String toString() => 'Owner identity rotated: pair this device again';
}

/// `ql.keyring.<ownerDeviceId>.qlk` — how a rotated household key reaches
/// active staff without re-pairing, and how revocation is signalled.
///
/// ```
/// { payload: { vault_id, epoch, issued_at, dev, hlc,
///              entries: { <staffId>: b64(AES-GCM(KEK_staff, K_shared[epoch])) },
///              revoked: [staffId, ...], rod: [ownerDeviceId, ...] },
///   sig: b64(Ed25519_owner(payload JSON)),
///   notices: [b64(SignedMarker by a REPLACED owner key), ...]   (optional) }
/// KEK_staff = HKDF(X25519(owner_sk, staff_pk), salt=vaultId, info="qlv/keyring/<staffId>/<epoch>")
/// ```
/// Only the owner and that staff device can derive KEK_staff; a revoked
/// device has no entry for the new epoch, so it cannot read anything
/// written after its revocation.
///
/// One file PER OWNER DEVICE (single writer, like every other cloud file):
/// two owner devices never overwrite each other's ring. Staff take the
/// newest valid ring that has an entry for them (highest epoch, then
/// highest HLC), ignore rings written by an owner device another ring
/// declares lost (`rod`), and treat being listed in ANY valid ring's
/// `revoked` as revocation.
class KeyRing {
  KeyRing({
    required this.vaultId,
    required this.epoch,
    required this.entries,
    required this.revoked,
    required this.issuedAt,
    this.isolated = false,
    this.writer,
    this.hlc = '',
    this.revokedOwners = const [],
  });

  /// Per-staff channels: each entry wraps THAT staff member's own K_staff
  /// (not a shared household key). Phones on the previous app version see
  /// a normal key rotation; current phones switch to channel sync.
  final bool isolated;

  final String vaultId;
  final int epoch;
  final Map<String, String> entries;
  final List<String> revoked;
  final int issuedAt;

  /// Owner device that wrote this ring (null: legacy shared file).
  final String? writer;

  /// Writer's HLC when built ('' on legacy rings): orders rings of equal epoch.
  final String hlc;

  /// Owner devices declared lost (their rings are ignored).
  final List<String> revokedOwners;

  /// Legacy single file shared by every owner device (older app versions).
  static const legacyFileName = 'ql.keyring.qlk';
  /// Same as [legacyFileName] (kept for existing callers). New rings are
  /// per owner device: [fileNameFor]; match any ring with [isRingName].
  static const fileName = legacyFileName;

  static const prefix = 'ql.keyring.';
  static String fileNameFor(String ownerDeviceId) => 'ql.keyring.$ownerDeviceId.qlk';

  static final _name = RegExp(r'^ql\.keyring\.([0-9a-fA-F-]{8,64})\.qlk$');

  /// True for a per-device ring or the legacy ring.
  static bool isRingName(String name) => name == legacyFileName || _name.hasMatch(name);

  /// Writer device id encoded in a per-device ring name (null: legacy / other).
  static String? writerOf(String name) => _name.firstMatch(name)?.group(1);

  /// Newest first: higher epoch, then higher HLC, then later issue time.
  static int compareNewest(KeyRing a, KeyRing b) {
    if (a.epoch != b.epoch) return b.epoch.compareTo(a.epoch);
    final h = b.hlc.compareTo(a.hlc);
    if (h != 0) return h;
    return b.issuedAt.compareTo(a.issuedAt);
  }

  Map<String, Object?> _payload() => {
        'vault_id': vaultId,
        'epoch': epoch,
        'issued_at': issuedAt,
        'entries': entries,
        'revoked': revoked,
        if (isolated) 'iso': 1,
        if (writer != null) 'dev': writer,
        if (hlc.isNotEmpty) 'hlc': hlc,
        if (revokedOwners.isNotEmpty) 'rod': revokedOwners,
      };

  static List<int> _aad(String vaultId, String staffId, int epoch) => utf8.encode('qlv-keyring|$vaultId|$staffId|$epoch');

  static Future<Uint8List> _kek(List<int> ourSecret, List<int> theirPublic, String vaultId, String staffId, int epoch) async {
    final x = X25519();
    final kp = await x.newKeyPairFromSeed(ourSecret);
    final shared = await x.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(theirPublic, type: KeyPairType.x25519),
    );
    return hkdf(await shared.extractBytes(), salt: utf8.encode(vaultId), info: utf8.encode('qlv/keyring/$staffId/$epoch'));
  }

  // ------------------------------------------------------------- owner

  static Future<Uint8List> build({
    required String vaultId,
    required int epoch,
    required Uint8List householdKey,
    required Uint8List ownerX25519Secret,
    required Uint8List ownerSigningSeed,
    required Map<String, Uint8List> activeStaffPublicKeys, // staffId → X25519 pk
    required List<String> revoked,
    Map<String, Uint8List>? perStaffKeys, // staffId → K_staff (isolated channels)
    String? writerDeviceId,
    String hlc = '',
    List<String> revokedOwnerDevices = const [],
    List<String> identityNotices = const [], // base64 SignedMarkers by replaced owner keys
  }) async {
    final entries = <String, String>{};
    for (final e in activeStaffPublicKeys.entries) {
      final k = perStaffKeys == null ? householdKey : perStaffKeys[e.key];
      if (k == null) continue; // no channel key yet: no entry (cannot read anything)
      final kek = await _kek(ownerX25519Secret, e.value, vaultId, e.key, epoch);
      entries[e.key] = base64Encode(await Aead.seal(kek, k, aad: _aad(vaultId, e.key, epoch)));
      wipe(kek);
    }
    final ring = KeyRing(
      vaultId: vaultId,
      epoch: epoch,
      entries: entries,
      revoked: revoked,
      issuedAt: DateTime.now().toUtc().millisecondsSinceEpoch,
      isolated: perStaffKeys != null,
      writer: writerDeviceId,
      hlc: hlc,
      revokedOwners: revokedOwnerDevices,
    );
    final payload = utf8.encode(jsonEncode(ring._payload()));
    final kp = await Ed25519().newKeyPairFromSeed(ownerSigningSeed);
    final sig = await Ed25519().sign(payload, keyPair: kp);
    return Uint8List.fromList(utf8.encode(jsonEncode({
      'payload': base64Encode(payload),
      'sig': base64Encode(sig.bytes),
      if (identityNotices.isNotEmpty) 'notices': identityNotices,
    })));
  }

  // ------------------------------------------------------------- staff

  /// Verifies the owner's signature; throws [StateError] on tampering,
  /// [FormatException] on a structurally invalid file (never a TypeError),
  /// and [OwnerIdentityRotated] when the signature fails but a notice
  /// signed by [ownerSigningKey] says the owner replaced its keys (for
  /// [vaultId], when given).
  static Future<KeyRing> verify(Uint8List file, Uint8List ownerSigningKey, {String? vaultId}) async {
    final List<int> payload;
    final List<int> sig;
    final Object? notices;
    try {
      final j = jsonDecode(utf8.decode(file));
      if (j is! Map || j['payload'] is! String || j['sig'] is! String) throw const FormatException('Key-ring malformed');
      payload = base64Decode(j['payload'] as String);
      sig = base64Decode(j['sig'] as String);
      notices = j['notices'];
    } on FormatException {
      throw const FormatException('Key-ring malformed');
    }
    if (sig.length != 64 || ownerSigningKey.length != 32) throw StateError('Key-ring signature invalid');
    bool ok;
    try {
      ok = await Ed25519().verify(
        payload,
        signature: Signature(sig, publicKey: SimplePublicKey(ownerSigningKey, type: KeyPairType.ed25519)),
      );
    } catch (_) {
      ok = false;
    }
    if (!ok) {
      if (await _rotationNotice(notices, ownerSigningKey, vaultId)) throw const OwnerIdentityRotated();
      throw StateError('Key-ring signature invalid');
    }
    try {
      final p = jsonDecode(utf8.decode(payload)) as Map<String, dynamic>;
      return KeyRing(
        vaultId: p['vault_id'] as String,
        epoch: p['epoch'] as int,
        // Eager copies: a wrong element type fails here, not later.
        entries: Map<String, String>.from(p['entries'] as Map),
        revoked: List<String>.from(p['revoked'] as List),
        issuedAt: p['issued_at'] as int,
        isolated: p['iso'] == 1,
        writer: p['dev'] as String?,
        hlc: (p['hlc'] as String?) ?? '',
        revokedOwners: p['rod'] == null ? const [] : List<String>.from(p['rod'] as List),
      );
    } catch (_) {
      // Signed but unreadable (newer format?): treat as malformed.
      throw const FormatException('Key-ring malformed');
    }
  }

  /// A notice signed by the key this phone trusts, saying it was replaced.
  static Future<bool> _rotationNotice(Object? notices, List<int> trustedKey, String? vaultId) async {
    if (notices is! List) return false;
    for (final n in notices.take(8)) {
      if (n is! String) continue;
      final Uint8List bytes;
      try {
        bytes = base64Decode(n);
      } catch (_) {
        continue;
      }
      final p = await SignedMarker.verify(bytes, trustedKey);
      if (p == null || p['kind'] != SignedMarker.kindOwnerIdentityRotated) continue;
      if (vaultId != null && p['vault_id'] != vaultId) continue;
      return true;
    }
    return false;
  }

  /// Decrypt this staff device's household key, or null if not present (revoked).
  Future<Uint8List?> householdKeyFor({
    required String staffId,
    required Uint8List staffX25519Secret,
    required Uint8List ownerX25519Public,
  }) async {
    final e = entries[staffId];
    if (e == null) return null;
    final kek = await _kek(staffX25519Secret, ownerX25519Public, vaultId, staffId, epoch);
    try {
      return await Aead.open(kek, base64Decode(e), aad: _aad(vaultId, staffId, epoch));
    } finally {
      wipe(kek);
    }
  }
}
