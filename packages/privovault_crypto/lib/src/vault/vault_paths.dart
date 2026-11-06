import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// On-disk layout (Application Support, excluded from device backups):
///
///   vault/header.json            non-secret: vaultId, deviceId, role
///   vault/private.db             owner only, SQLCipher (K_private)
///   vault/shared.db              owner + staff, SQLCipher (K_shared)
///   vault/behavior_profile.qlb   AES-256-GCM JSON
///   vault/staff_credentials.qlc  staff only, AES-256-GCM JSON
class VaultPaths {
  VaultPaths._(this.dir);
  final Directory dir;

  static Future<VaultPaths> resolve() async {
    final base = await getApplicationSupportDirectory();
    final d = Directory(p.join(base.path, 'vault'));
    await d.create(recursive: true);
    return VaultPaths._(d);
  }

  String get privateDb => p.join(dir.path, 'private.db');
  String get sharedDb => p.join(dir.path, 'shared.db');
  File get header => File(p.join(dir.path, 'header.json'));
  File get behaviorProfile => File(p.join(dir.path, 'behavior_profile.qlb'));
  File get staffCredentials => File(p.join(dir.path, 'staff_credentials.qlc'));

  /// Two-phase key changes (see VaultHandshake): the next-key copy waits
  /// here until the new key is stored behind biometrics, then replaces the
  /// live file. An interrupted change is settled at the next unlock.
  String get pendingPrivateDb => '$privateDb.rekey';
  File get pendingBehaviorProfile => File('${behaviorProfile.path}.rekey');
  File get pendingStaffCredentials => File('${staffCredentials.path}.pending');
  Directory get scratch => Directory(p.join(dir.path, 'tmp'));

  /// Emergency-Kit rotation not yet confirmed (see
  /// `VaultHandshake.kitRotationReverted`). Kept OUTSIDE the pending files,
  /// which an unlock may discard. Non-secret: a hash of the new recovery
  /// wrap (itself public in every package header) and a state.
  File get kitRotationFlag => File(p.join(dir.path, 'kit_rotation.json'));

  Future<VaultHeader?> readHeader() async {
    if (!await header.exists()) return null;
    return VaultHeader.fromJson(jsonDecode(await header.readAsString()) as Map<String, dynamic>);
  }

  Future<void> writeHeader(VaultHeader h) async {
    final tmp = File('${header.path}.tmp');
    await tmp.writeAsString(jsonEncode(h.toJson()), flush: true);
    await tmp.rename(header.path);
  }

  /// Securely discard all local vault files (sign-out / revoked staff).
  Future<void> wipeAll() async {
    if (await dir.exists()) {
      for (final f in dir.listSync(recursive: true).whereType<File>()) {
        try {
          final len = await f.length();
          await f.writeAsBytes(List.filled(len, 0), flush: true); // best effort on flash
        } catch (_) {}
      }
      await dir.delete(recursive: true);
    }
    await dir.create(recursive: true);
  }
}

class VaultHeader {
  const VaultHeader({required this.vaultId, required this.deviceId, required this.role, required this.createdAt});
  final String vaultId;
  final String deviceId;
  final String role; // 'owner' | 'staff'
  final int createdAt;

  Map<String, dynamic> toJson() => {'v': 1, 'vault_id': vaultId, 'device_id': deviceId, 'role': role, 'created_at': createdAt};
  factory VaultHeader.fromJson(Map<String, dynamic> j) => VaultHeader(
        vaultId: j['vault_id'] as String,
        deviceId: j['device_id'] as String,
        role: j['role'] as String,
        createdAt: j['created_at'] as int,
      );
}
