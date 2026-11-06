import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'aead.dart';

/// Purpose-separated keys derived from the 256-bit Master Key (MK).
///
///   MK ──HKDF-SHA256(salt = vaultId)──┬─ info "qlv/sqlcipher/v1" → SQLCipher key
///                                     ├─ info "qlv/behavior/v1"  → behavior profile AES-GCM
///                                     └─ info "qlv/sync/v1"      → cloud package AES-GCM
///
/// Compromise of one derived key never exposes the others or the MK.
class VaultKeys {
  VaultKeys._(this.sqlcipher, this.behavior, this.sync);

  final Uint8List sqlcipher;
  final Uint8List behavior;
  final Uint8List sync;

  static Future<VaultKeys> derive(Uint8List masterKey, String vaultId) async {
    if (masterKey.length != 32) throw ArgumentError('Master key must be 32 bytes');
    final salt = utf8.encode(vaultId);
    Future<Uint8List> d(String info) => hkdf(masterKey, salt: salt, info: utf8.encode(info));
    return VaultKeys._(
      await d('qlv/sqlcipher/v1'),
      await d('qlv/behavior/v1'),
      await d('qlv/sync/v1'),
    );
  }

  void wipeAll() {
    wipe(sqlcipher);
    wipe(behavior);
    wipe(sync);
  }
}

Future<Uint8List> hkdf(List<int> ikm, {required List<int> salt, required List<int> info, int length = 32}) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: length)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await k.extractBytes());
}

/// Keys derived from the household root key K_shared (one per key epoch).
/// Owner and every active staff device hold K_shared; nothing derived from
/// the Owner Master Key is ever shared.
class SharedKeys {
  SharedKeys._(this.root, this.sqlcipher, this.sync, this.epoch);

  final Uint8List root;
  final Uint8List sqlcipher;
  final Uint8List sync;
  final int epoch;

  static Future<SharedKeys> derive(Uint8List householdKey, String vaultId, int epoch) async {
    if (householdKey.length != 32) throw ArgumentError('Household key must be 32 bytes');
    final salt = utf8.encode(vaultId);
    return SharedKeys._(
      Uint8List.fromList(householdKey),
      await hkdf(householdKey, salt: salt, info: utf8.encode('qlv/shared-sqlcipher/v1')),
      await hkdf(householdKey, salt: salt, info: utf8.encode('qlv/shared-sync/v1')),
      epoch,
    );
  }

  void wipeAll() {
    wipe(root);
    wipe(sqlcipher);
    wipe(sync);
  }
}

/// Device-local keys for a staff device, derived from that device's own
/// hardware-protected master key (never related to the owner's keys).
class StaffDeviceKeys {
  StaffDeviceKeys._(this.credentials, this.behavior);
  final Uint8List credentials;
  final Uint8List behavior;

  static Future<StaffDeviceKeys> derive(Uint8List deviceMasterKey, String deviceId) async {
    final salt = utf8.encode(deviceId);
    return StaffDeviceKeys._(
      await hkdf(deviceMasterKey, salt: salt, info: utf8.encode('qlv/staff-creds/v1')),
      await hkdf(deviceMasterKey, salt: salt, info: utf8.encode('qlv/staff-behavior/v1')),
    );
  }

  void wipeAll() {
    wipe(credentials);
    wipe(behavior);
  }
}
