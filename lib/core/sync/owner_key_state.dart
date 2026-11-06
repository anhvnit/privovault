import 'dart:convert';
import 'dart:typed_data';

import '../crypto/aead.dart' show sha256;
import '../db/vault_database.dart';
import '../db/vault_database_service.dart';
import '../roles.dart' show OwnerOnlyAccess;
import '../util/home_currency.dart' show isOfferedBaseCurrency;
import 'staff_channel.dart' show StaffChannel;

/// Key and channel state every OWNER device must agree on (audit H1).
///
/// `vault_meta` is device-local (never merged), yet the household epoch and
/// keys, `staff_channel_mode` and the `staff_grant:*` tokens are written on
/// whichever owner device acted. They now also live in the replicated
/// private table `owner_key_state`, so they reach the owner's other devices
/// inside the owner private package (sealed under the master-key-derived
/// sync key, owner-signed). `vault_meta` stays the device's working copy:
/// the handshake opens shared.db from it and existing code keeps reading
/// and writing it. [reconcile] keeps the two in step on every owner sync.
///
/// Rows (`id` → `value`):
///  * `hk:<epoch>:<fp>` → base64 household key of that generation. Insert
///    only, never updated or deleted: every key any owner device ever used
///    stays readable (old staff / peer files). Two devices that created a
///    key for the same epoch both keep theirs; the deterministic winner is
///    the LOWEST fingerprint ([fingerprint]). The current epoch is the
///    highest one present (never decreases).
///  * `staff_channel_mode` → `'1'` once any device moved to per-staff
///    channels (monotonic).
///  * `staff_grant:<staffId>` → the delegated cloud grant JSON (three-way
///    merged with `vault_meta`, tombstoned when forgotten).
///  * `odr:<deviceId>` → `{"at":ms,"by":deviceId}`: that OWNER device was
///    declared lost. Every owner device refuses and deletes its packages.
///    Never cleared.
///  * `owner_identity_rotated_at` → ms of the last owner identity rotation
///    (monotonic max): staff paired before it must pair again.
///  * `base_currency` → the vault's base currency (ISO code). Written in
///    the same transaction as `vault_meta` by [setBaseCurrency], so the row
///    is the authority: last writer (HLC) wins across owner devices, and
///    [reconcile] copies it into `vault_meta` (private + shared).
class OwnerKeyState {
  OwnerKeyState(this.db);
  final VaultDatabase db;

  static const table = 'owner_key_state';

  /// `vault_meta`: last values reconciled per three-way-merged key (JSON).
  static const _mirrorMeta = 'oks.mirror';

  /// `vault_meta`: alternative (tie-break losing) household keys this
  /// device knows, so its shared.db still opens after a crash mid re-key
  /// and old files sealed under them stay readable. Read by the handshake.
  static String altKeyMeta(int epoch, String fp) => OwnerMeta.householdKeyAlt(epoch, fp);

  static String hkId(int epoch, String fp) => 'hk:$epoch:$fp';
  static String revokedDeviceId(String deviceId) => 'odr:${deviceId.toLowerCase()}';
  static const identityRotatedAt = 'owner_identity_rotated_at';
  static const baseCurrencyId = 'base_currency';

  static final _hkRow = RegExp(r'^hk:(\d+):([0-9a-f]{16})$');
  static final _hkMeta = RegExp(r'^household_key_e(\d+)$');
  static final _hkAltMeta = RegExp(r'^household_key_e(\d+)_alt_([0-9a-f]{16})$');

  /// Public, non-reversible fingerprint of a household key (16 hex chars).
  static Future<String> fingerprint(List<int> key) async {
    final h = await sha256([...utf8.encode('qlv/hk-fp|'), ...key]);
    return h.take(8).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List? _decodeKey(String? b64) {
    if (b64 == null) return null;
    try {
      final k = base64Decode(b64);
      return k.length == 32 ? k : null;
    } catch (_) {
      return null;
    }
  }

  // ------------------------------------------------------------ queries

  /// Owner devices declared lost (lower-case ids).
  Future<Set<String>> revokedDevices({VaultExecutor? tx}) async {
    if (!db.hasPrivate) return const {};
    final rows = await (tx ?? db).select("SELECT id FROM main.$table WHERE id LIKE 'odr:%' AND deleted_at IS NULL");
    return {for (final r in rows) (r['id']! as String).substring(4)};
  }

  /// Every household key known for [epoch] (any device), winner first.
  Future<List<Uint8List>> householdKeys(int epoch) async {
    final out = <(String, Uint8List)>[];
    final rows = await db.select(
        "SELECT id, value FROM main.$table WHERE id LIKE ? AND deleted_at IS NULL", ['hk:$epoch:%']);
    for (final r in rows) {
      final m = _hkRow.firstMatch(r['id']! as String);
      final k = _decodeKey(r['value'] as String?);
      if (m == null || k == null || int.parse(m.group(1)!) != epoch) continue;
      out.add((m.group(2)!, k));
    }
    // Keys only this device knows (not exported yet, e.g. right after a
    // crash) still count.
    final metaRows = await db.select("SELECT key, value FROM main.vault_meta WHERE key LIKE 'household_key_e%'");
    for (final r in metaRows) {
      final key = r['key'];
      if (key is! String) continue;
      final m = _hkMeta.firstMatch(key) ?? _hkAltMeta.firstMatch(key);
      if (m == null || int.parse(m.group(1)!) != epoch) continue;
      final k = _decodeKey(r['value'] as String?);
      if (k == null) continue;
      final fp = await fingerprint(k);
      if (out.any((e) => e.$1 == fp)) continue;
      out.add((fp, k));
    }
    out.sort((a, b) => a.$1.compareTo(b.$1));
    return [for (final e in out) e.$2];
  }

  /// Declare other OWNER devices lost: from now on every owner device
  /// ignores, deletes and refuses their packages (they ride to the other
  /// devices in this device's owner-signed private package).
  Future<void> declareDevicesLost(Iterable<String> deviceIds, {required String byDeviceId}) async {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch;
    await db.transaction((tx) async {
      final known = await revokedDevices(tx: tx);
      for (final id in deviceIds) {
        final lid = id.toLowerCase();
        if (lid == byDeviceId.toLowerCase() || known.contains(lid)) continue;
        await tx.upsert(table, {
          'id': revokedDeviceId(lid),
          'value': jsonEncode({'at': now, 'by': byDeviceId}),
          'deleted_at': null,
        });
      }
    });
  }

  /// When the owner identity keys were last rotated (null = never).
  Future<int?> identityRotatedAtMs() async => int.tryParse(await db.meta(identityRotatedAt) ?? '');

  /// Active staff paired BEFORE the last owner identity rotation: their
  /// phones still trust the old owner keys and must be paired again.
  static Future<Set<String>> staffNeedingRepair(VaultDatabase db) async {
    if (!db.hasPrivate) return const {};
    final at = int.tryParse(await db.meta(identityRotatedAt) ?? '');
    if (at == null) return const {};
    final rows = await db.select(
      'SELECT id FROM ${db.qualified('staff_members', DataScope.shared)} '
      'WHERE revoked_at IS NULL AND deleted_at IS NULL AND (paired_at IS NULL OR paired_at < ?)',
      [at],
    );
    return {for (final r in rows) r['id']! as String};
  }

  /// Owner: change the vault's base currency. One transaction writes the
  /// device's working copy (private `vault_meta`), the household-visible
  /// copy (shared `vault_meta`) and the replicated row that carries the
  /// change to the owner's other devices. Callers then update the open
  /// session (VaultSessionController.setBaseCurrency).
  Future<void> setBaseCurrency(String code) async {
    if (!db.hasPrivate) throw OwnerOnlyAccess('setBaseCurrency');
    if (!isOfferedBaseCurrency(code)) throw ArgumentError.value(code, 'code', 'not an offered base currency');
    await db.transaction((tx) async {
      await db.setMeta(OwnerMeta.baseCurrency, code, tx: tx);
      await db.setSharedMeta(SharedMeta.baseCurrency, code, tx: tx);
      await tx.upsert(table, {'id': baseCurrencyId, 'value': code, 'deleted_at': null});
    });
  }

  // --------------------------------------------------------- reconcile

  /// Two-way reconciliation of this device's `vault_meta` with the
  /// replicated table. Idempotent, writes only what changed, owner only.
  /// Run after merging other owner devices' private packages and before
  /// pushing ours. A raised `household_epoch` (or a same-epoch key that
  /// lost the tie-break) is then adopted by the sync engine (re-key).
  Future<void> reconcile() async {
    if (!db.hasPrivate) return;
    await db.transaction((tx) async {
      final meta = <String, String>{
        for (final r in await tx.select(
            "SELECT key, value FROM main.vault_meta WHERE key LIKE 'household_%' OR key LIKE 'staff_%' "
            'OR key = ? OR key = ? OR key = ?',
            [_mirrorMeta, identityRotatedAt, OwnerMeta.baseCurrency]))
          if (r['key'] is String && r['value'] is String) r['key']! as String: r['value']! as String,
      };
      final rows = <String, ({String? value, bool deleted})>{
        for (final r in await tx.select('SELECT id, value, deleted_at FROM main.$table'))
          r['id']! as String: (value: r['value'] as String?, deleted: r['deleted_at'] != null),
      };
      String? live(String id) {
        final r = rows[id];
        return r == null || r.deleted ? null : r.value;
      }

      Future<void> putRow(String id, String value) async {
        await tx.upsert(table, {'id': id, 'value': value, 'deleted_at': null});
        rows[id] = (value: value, deleted: false);
      }

      Future<void> putMeta(String key, String value) async {
        await db.setMeta(key, value, tx: tx);
        meta[key] = value;
      }

      // 1) Household keys: export every key this device holds ...
      for (final e in meta.entries) {
        final m = _hkMeta.firstMatch(e.key) ?? _hkAltMeta.firstMatch(e.key);
        final k = _decodeKey(e.value);
        if (m == null || k == null) continue;
        final epoch = int.parse(m.group(1)!);
        final fp = await fingerprint(k);
        if (!rows.containsKey(hkId(epoch, fp))) await putRow(hkId(epoch, fp), e.value);
      }
      // ... then import: per epoch the lowest fingerprint is THE key; the
      // others stay reachable as alternatives.
      final byEpoch = <int, List<(String, String)>>{};
      for (final e in rows.entries) {
        final m = _hkRow.firstMatch(e.key);
        final v = e.value.value;
        if (m == null || e.value.deleted || _decodeKey(v) == null) continue;
        (byEpoch[int.parse(m.group(1)!)] ??= []).add((m.group(2)!, v!));
      }
      var maxEpoch = int.tryParse(meta[OwnerMeta.householdEpoch] ?? '') ?? 0;
      for (final entry in byEpoch.entries) {
        final epoch = entry.key;
        final keys = entry.value..sort((a, b) => a.$1.compareTo(b.$1));
        if (epoch > maxEpoch) maxEpoch = epoch;
        final winner = keys.first;
        final localB64 = meta[OwnerMeta.householdKey(epoch)];
        final local = _decodeKey(localB64);
        if (local == null) {
          await putMeta(OwnerMeta.householdKey(epoch), winner.$2);
        } else {
          final localFp = await fingerprint(local);
          if (localFp != winner.$1) {
            // Lost the tie-break: keep ours as an alternative FIRST, so
            // shared.db (still keyed with it) opens if we crash before
            // the re-key, then switch to the winner.
            await putMeta(altKeyMeta(epoch, localFp), localB64!);
            await putMeta(OwnerMeta.householdKey(epoch), winner.$2);
          }
        }
        for (final k in keys.skip(1)) {
          if (meta[altKeyMeta(epoch, k.$1)] == null) await putMeta(altKeyMeta(epoch, k.$1), k.$2);
        }
      }
      final localEpoch = int.tryParse(meta[OwnerMeta.householdEpoch] ?? '');
      if (maxEpoch > 0 && (localEpoch == null || maxEpoch > localEpoch)) {
        await putMeta(OwnerMeta.householdEpoch, '$maxEpoch');
      }

      // 2) Channel mode: once on anywhere, on everywhere.
      const mode = StaffChannel.modeMetaKey;
      if (meta[mode] == '1' && live(mode) != '1') await putRow(mode, '1');
      if (live(mode) == '1' && meta[mode] != '1') await putMeta(mode, '1');

      // 3) Identity rotation time: monotonic max.
      final idLocal = int.tryParse(meta[identityRotatedAt] ?? '');
      final idRemote = int.tryParse(live(identityRotatedAt) ?? '');
      if (idLocal != null && (idRemote == null || idLocal > idRemote)) await putRow(identityRotatedAt, '$idLocal');
      if (idRemote != null && (idLocal == null || idRemote > idLocal)) await putMeta(identityRotatedAt, '$idRemote');

      // 4) Staff grants: three-way merge against the last reconciled value,
      //    so a local change (pairing, back-off, forget) and a remote one
      //    are told apart. LWW across devices happens in the table.
      final mirror = <String, String>{};
      try {
        final j = jsonDecode(meta[_mirrorMeta] ?? '{}');
        if (j is Map) {
          for (final e in j.entries) {
            if (e.key is String && e.value is String) mirror[e.key as String] = e.value as String;
          }
        }
      } catch (_) {}
      final before = jsonEncode(mirror);
      const grantPrefix = 'staff_grant:';
      final grantKeys = <String>{
        for (final k in meta.keys)
          if (k.startsWith(grantPrefix)) k,
        for (final k in rows.keys)
          if (k.startsWith(grantPrefix)) k,
        for (final k in mirror.keys)
          if (k.startsWith(grantPrefix)) k,
      };
      for (final k in grantKeys) {
        final local = meta[k];
        final remote = live(k);
        final base = mirror[k];
        String? settled;
        if (local == remote) {
          settled = local;
        } else if (local != base) {
          // Changed here.
          if (local == null) {
            if (rows[k] != null && !rows[k]!.deleted) {
              await tx.softDelete(table, k);
              rows[k] = (value: rows[k]!.value, deleted: true);
            }
          } else {
            await putRow(k, local);
          }
          settled = local;
        } else {
          // Changed on another owner device.
          if (remote == null) {
            await tx.execute('DELETE FROM main.vault_meta WHERE key = ?', [k], {'vault_meta'});
            meta.remove(k);
          } else {
            await putMeta(k, remote);
          }
          settled = remote;
        }
        if (settled == null) {
          mirror.remove(k);
        } else {
          mirror[k] = settled;
        }
      }
      final after = jsonEncode(mirror);
      if (after != before) await db.setMeta(_mirrorMeta, after, tx: tx);

      // 5) Base currency: only ever written together with vault_meta
      //    ([setBaseCurrency]), so the replicated row wins. No row yet
      //    (never changed since onboarding): every device keeps its own.
      //    Validated like any value from another device: an ISO-shaped
      //    code from the offered list, else ignored (local one kept).
      final currency = live(baseCurrencyId);
      if (isOfferedBaseCurrency(currency)) {
        if (meta[OwnerMeta.baseCurrency] != currency) await putMeta(OwnerMeta.baseCurrency, currency!);
        if (await db.sharedMeta(SharedMeta.baseCurrency, tx: tx) != currency) {
          await db.setSharedMeta(SharedMeta.baseCurrency, currency!, tx: tx);
        }
      }
    });
  }
}
