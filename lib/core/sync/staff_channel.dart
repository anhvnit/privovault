import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:privovault_crypto/privovault_crypto.dart' show newId;

import '../crypto/aead.dart';
import '../crypto/vault_keys.dart';
import '../db/vault_database.dart';
import '../db/vault_database_service.dart';
import 'cloud/cloud_store.dart';
import 'cloud/household_store.dart';
import 'keyring.dart' show KeyRing;
import 'merge_engine.dart';
import 'package_format.dart';
import 'snapshot.dart';
import 'sync_engine.dart' show SyncEngine;

// ======================================================================
// Per-staff isolated channels
// ======================================================================
//
// Every staff phone talks to the owner through its OWN pair of files,
// encrypted with its OWN key K_staff, inside its OWN sub-folder of the
// household space (see cloud/household_store.dart) — a cloud space separate
// from the owner's packages, so the phone's token cannot reach them:
//
//   staff_<staff_id>.db        written ONLY by that staff phone — the rows
//                              it authored (expenses, fuel, trips, chat…),
//                              signed with the phone's Ed25519 key.
//   staff_<staff_id>.owner.db  written ONLY by owner devices — that phone's
//                              view: categories, the cars it may log, its
//                              own profile/limits, and the owner's decisions
//                              on its entries (approved / reimbursed).
//
// Two files, not one, because cloud folders have no locking: a file with
// two writers loses updates. Each file has exactly one writer; readers
// merge rows by HLC (see MergeEngine).
//
// Isolation, enforced in three layers:
//  1. Cryptographic — K_staff_A decrypts only A's two files. The owner's
//     household snapshot (ql.shared.*) is under K_shared, which no staff
//     phone holds any more. A compromised phone exposes its own entries
//     and nothing else.
//  2. Content — the owner's view for A is built by pruning a snapshot to
//     A's rows (secure_delete + VACUUM, so no deleted pages survive), and
//     the staff phone uploads only rows it authored.
//  3. Access pattern — staff clients never LIST the folder; they fetch
//     their three files by exact name (CloudStore.stat).
//  4. Storage — channels live in the household space, never in the owner's
//     own app folder; staff tokens are minted for that space only.
//
// The owner's per-staff keys live in private.db (`staff_channel_keys`),
// i.e. under the owner's hardware-released master key (Secure Enclave /
// StrongBox + biometrics), and sync to the owner's other devices only.

abstract final class StaffChannel {
  static const prefix = 'staff_';
  static String staffFile(String staffId) => 'staff_$staffId.db';
  static String ownerFile(String staffId) => 'staff_$staffId.owner.db';

  static ({String staffId, bool ownerView})? parse(String name) {
    final m = RegExp(r'^staff_([0-9a-fA-F-]{8,64})(\.owner)?\.db$').firstMatch(name);
    if (m == null) return null;
    return (staffId: m.group(1)!, ownerView: m.group(2) != null);
  }

  /// Staff ids are UUIDs (they name cloud files and household folders).
  static final _uuid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');
  static bool isStaffId(Object? id) => id is String && _uuid.hasMatch(id);

  /// Key-ring flag: staff devices switch to channel sync when they see it.
  static const modeMetaKey = 'staff_channel_mode';
}

/// One staff member's channel key, as the owner holds it.
class StaffChannelKey {
  const StaffChannelKey(this.staffId, this.key, this.generation);
  final String staffId;
  final Uint8List key;
  final int generation;

  /// Same derivation the staff phone uses for its local DB + channel files.
  Future<SharedKeys> derive(String vaultId) => SharedKeys.derive(key, vaultId, generation);
}

// ======================================================================
// Owner: per-staff key store
// ======================================================================

class StaffChannelKeyStore {
  StaffChannelKeyStore(this.db);
  final VaultDatabase db;

  /// Generation used for new keys. Strictly above every household epoch a
  /// staff phone has seen, so phones on the previous app version treat
  /// their channel key as a normal key rotation (backwards compatible).
  ///
  /// Pass [tx] when called inside a transaction: touching the outer
  /// database from inside one deadlocks (sqflite queues it behind the tx).
  Future<int> currentGeneration({VaultExecutor? tx}) async {
    final r = await (tx ?? db).selectOne('SELECT max(generation) AS g FROM staff_channel_keys');
    final g = r?['g'] as int?;
    if (g != null) return g;
    final epoch = int.tryParse(await db.meta(OwnerMeta.householdEpoch, tx: tx) ?? '') ?? 1;
    return epoch + 1;
  }

  /// A fresh, unique K_staff for [staffId] (new pairing or migration).
  Future<StaffChannelKey> create(String staffId, {VaultExecutor? tx}) async {
    final key = randomBytes(32);
    final gen = await currentGeneration(tx: tx);
    await (tx ?? db).upsert('staff_channel_keys', {
      'id': staffId,
      'key_b64': base64Encode(key),
      'generation': gen,
      'deleted_at': null,
    });
    return StaffChannelKey(staffId, key, gen);
  }

  Future<StaffChannelKey?> keyFor(String staffId, {VaultExecutor? tx}) async {
    final r = await (tx ?? db).selectOne(
        'SELECT key_b64, generation FROM staff_channel_keys WHERE id = ? AND deleted_at IS NULL', [staffId]);
    if (r == null) return null;
    return StaffChannelKey(staffId, base64Decode(r['key_b64']! as String), r['generation']! as int);
  }

  /// Keys of staff members who are paired and not revoked.
  Future<List<StaffChannelKey>> active() async {
    final rows = await db.select(
      'SELECT k.id, k.key_b64, k.generation FROM staff_channel_keys k '
      'JOIN ${db.qualified('staff_members', DataScope.shared)} s ON s.id = k.id '
      'WHERE k.deleted_at IS NULL AND s.revoked_at IS NULL AND s.deleted_at IS NULL',
    );
    return [
      for (final r in rows)
        StaffChannelKey(r['id']! as String, base64Decode(r['key_b64']! as String), r['generation']! as int),
    ];
  }

  /// Revocation: the key is destroyed (tombstoned) on every owner device.
  Future<void> destroy(String staffId) => db.softDelete('staff_channel_keys', staffId);
}

// ======================================================================
// Pruned snapshots (what goes INTO each channel file)
// ======================================================================

/// SQL run against the attached snapshot (`snap`) before its bytes are
/// read. `secure_delete` + `VACUUM` guarantee that pruned rows leave no
/// trace in free pages of the uploaded file.
abstract final class ChannelPruning {
  static const _authorTables = ['household_expenses', 'household_chat', 'mileage_trips', 'household_recurring'];
  static const _linkedVehicleLogs = ['fuel_logs', 'service_records'];

  /// The owner's view for one staff member.
  static List<String> ownerView(String staffId, {Set<String>? vehicleIds}) {
    final s = _lit(staffId);
    final cars = vehicleIds == null ? null : '(${vehicleIds.map(_lit).join(',')})';
    return [
      'PRAGMA snap.secure_delete = ON',
      'DELETE FROM snap.vault_meta',
      'DELETE FROM snap.sync_conflicts',
      'DELETE FROM snap.staff_members WHERE id <> $s',
      // Insurance premiums, owner reminders: owner-only.
      'DELETE FROM snap.vehicle_compliance',
      'DELETE FROM snap.reminders',
      if (cars != null) 'DELETE FROM snap.vehicles WHERE id NOT IN $cars',
      if (cars != null) 'DELETE FROM snap.odometer_readings WHERE vehicle_id NOT IN $cars',
      for (final t in _authorTables) 'DELETE FROM snap.$t WHERE author_device_id <> $s',
      // Fuel / service records: keep those this phone wrote or that belong
      // to one of its expenses (amount-bearing rows of others go).
      for (final t in _linkedVehicleLogs)
        'DELETE FROM snap.$t WHERE substr(hlc, 22) <> $s '
            'AND (transaction_id IS NULL OR transaction_id NOT IN (SELECT id FROM snap.household_expenses))',
      'VACUUM snap',
    ];
  }

  /// What a staff phone uploads: only rows it authored.
  static List<String> staffUpload(String staffId) {
    final s = _lit(staffId);
    return [
      'PRAGMA snap.secure_delete = ON',
      'DELETE FROM snap.vault_meta',
      'DELETE FROM snap.sync_conflicts',
      for (final t in ['categories', 'vehicles', 'staff_members', 'vehicle_compliance', 'reminders']) 'DELETE FROM snap.$t',
      for (final t in _authorTables) 'DELETE FROM snap.$t WHERE author_device_id <> $s',
      for (final t in [..._linkedVehicleLogs, 'odometer_readings']) 'DELETE FROM snap.$t WHERE substr(hlc, 22) <> $s',
      'VACUUM snap',
    ];
  }

  /// One-time clean-up when a phone moves from the household model to its
  /// own channel: rows of OTHER staff it received under the old model are
  /// removed locally (hard delete — they belong to someone else).
  static List<String> purgeForeign(String staffId) {
    final s = _lit(staffId);
    return [
      'PRAGMA secure_delete = ON',
      'DELETE FROM staff_members WHERE id <> $s',
      'DELETE FROM vehicle_compliance',
      'DELETE FROM reminders',
      for (final t in _authorTables) 'DELETE FROM $t WHERE author_device_id <> $s',
      for (final t in _linkedVehicleLogs)
        'DELETE FROM $t WHERE substr(hlc, 22) <> $s '
            'AND (transaction_id IS NULL OR transaction_id NOT IN (SELECT id FROM household_expenses))',
      'DELETE FROM vault_meta WHERE key LIKE \'sync.%\'',
    ];
  }

  static String _lit(String s) => "'${s.replaceAll("'", "''")}'";
}

extension PrunedSnapshot on SnapshotService {
  /// Like [SnapshotService.export] for the shared scope, then runs [prune]
  /// on the copy. The live database is never modified.
  ///
  /// The prune runs on a SEPARATE connection opened on the staged copy with
  /// `foreign_keys = OFF`: the pruned copy legitimately drops parents
  /// (categories, vehicles) whose children stay, which raises
  /// "FOREIGN KEY constraint failed" on a connection with FKs on. Toggling
  /// the pragma on the live connection instead would let concurrent app
  /// writes run unchecked, so the live database is never touched.
  Future<Uint8List> exportPruned(VaultDatabase db, Uint8List sqlcipherKey, List<String> prune) async {
    final bytes = await export(db, DataScope.shared, sqlcipherKey);
    final f = await stage(bytes, 'prune');
    try {
      final c = await VaultDatabase.openKeyed(f.path, sqlcipherKey);
      try {
        await c.execute('PRAGMA foreign_keys = OFF');
        // openKeyed switches to WAL; keep the uploaded file a plain
        // rollback-journal database like sqlcipher_export produces.
        await c.rawQuery('PRAGMA journal_mode = DELETE');
        for (final raw in prune) {
          // The pruning SQL targets the copy as `snap`; here it is `main`.
          final sql = raw == 'VACUUM snap' ? 'VACUUM' : raw.replaceAll('snap.', '');
          sql.startsWith('PRAGMA') || sql.startsWith('VACUUM') ? await c.rawQuery(sql) : await c.execute(sql);
        }
      } finally {
        await c.close();
      }
      return await f.readAsBytes();
    } finally {
      await discard(f);
    }
  }
}

// ======================================================================
// Shared push / pull of one channel file
// ======================================================================

class ChannelReport {
  final pulled = <String>[];
  final pushed = <String>[];
  final rejected = <String, String>{};
  int conflicts = 0;
  int rowsRejected = 0;
  int rowsDeferred = 0;
}

class _ChannelIO {
  _ChannelIO({required this.vault, required this.store, required this.snapshots});
  final UnlockedVault vault;
  final CloudStore store;
  final SnapshotService snapshots;
  VaultDatabase get db => vault.db;

  Future<Map<String, dynamic>?> readState(String key) async {
    final v = await db.meta('sync.$key');
    return v == null ? null : jsonDecode(v) as Map<String, dynamic>;
  }

  Future<void> writeState(String key, Map<String, Object?> value) => SyncEngine.writeStateIfChanged(db, key, value);

  /// Download, verify signature, decrypt and merge [o] if it changed.
  Future<void> pull({
    required CloudStore from,
    required RemoteObject o,
    required String stateKey,
    required SharedKeys keys,
    required List<int> signerPublicKey,
    required String expectedSigner, // 'owner' | 'staff'
    required String? expectedDeviceId,
    required PeerAuthority authority,
    required ChannelReport report,
  }) async {
    final prev = await readState(stateKey);
    if (SyncEngine.unchangedSinceMerge(prev, o.version)) return;
    final sealed = SealedPackage.parse(await from.downloadCapped(o, CloudLimits.maxPackageBytes));
    final h = sealed.header;
    if (h.vaultId != vault.vaultId) throw PackageTampered('foreign vault');
    if (h.scope != DataScope.shared) throw PackageTampered('wrong scope');
    if (h.signer != expectedSigner) throw PackageTampered('unexpected signer');
    if (expectedDeviceId != null && h.deviceId != expectedDeviceId) throw PackageTampered('name/header mismatch');
    await sealed.verify(signerPublicKey);
    final contents = await sealed.open(keys.sync);
    final staged = await snapshots.stage(contents.database, 'chan');
    try {
      final r = await MergeEngine(db).merge(
        peerFile: staged,
        peerSqlcipherKey: keys.sqlcipher,
        scope: DataScope.shared,
        peerDeviceId: h.deviceId,
        authority: authority,
        baseHlc: (prev?['max_hlc'] as String?) ?? '',
      );
      report.conflicts += r.conflicts;
      report.rowsRejected += r.rejectedByAuthority;
      report.rowsDeferred += r.deferredFuture;
      await writeState(stateKey, SyncEngine.mergeState(o.version, r, prev));
      report.pulled.add(o.name);
    } finally {
      await snapshots.discard(staged);
    }
  }

  /// Seal [dbBytes] and upload as [name] (skips when [fingerprint] and the
  /// remote copy are unchanged since the last push).
  Future<void> push({
    required CloudStore to,
    required String name,
    required String stateKey,
    required String fingerprint,
    required SharedKeys keys,
    required Uint8List signingSeed,
    required String signer,
    required Future<Uint8List> Function() build,
    required ChannelReport report,
  }) async {
    final existing = await to.stat(name);
    final prev = await readState(stateKey);
    if (existing != null && existing.version == prev?['version'] && prev?['fp'] == fingerprint) return;
    final dbBytes = await build();
    final createdAt = DateTime.now().toUtc().millisecondsSinceEpoch;
    final maxHlc = await db.maxHlc(DataScope.shared);
    final bytes = await SealedPackage.build(
      header: (hash) => PackageHeader(
        scope: DataScope.shared,
        vaultId: vault.vaultId,
        deviceId: vault.deviceId,
        signer: signer,
        schemaVersion: privoVaultSchema.sharedVersion,
        createdAt: createdAt,
        maxHlc: maxHlc,
        bodySha256: hash,
        keyEpoch: keys.epoch,
      ),
      syncKey: keys.sync,
      signingSeed: signingSeed,
      database: dbBytes,
    );
    final up = await to.put(name, bytes, existing: existing);
    await writeState(stateKey, {'version': up.version, 'fp': fingerprint});
    report.pushed.add(name);
  }
}

// ======================================================================
// Owner: Multi-DB manager + aggregation engine
// ======================================================================

/// Owner side of the channels. Runs inside every owner sync pass (after
/// the owner-device peers), never on the UI isolate's critical path —
/// all I/O is async and SQLCipher work runs on the plugin's DB thread.
///
/// Per active staff member S:
///   1. pull  staff_S.db       (if changed) → verify S's signature →
///      decrypt with K_S → merge with STAFF authority (only rows S
///      authored are accepted) into the owner's shared.db — so every
///      staff expense lands in the owner's dashboards and cash flow.
///   2. push  staff_S.owner.db (if the owner's data changed) → S's view.
/// Then: delete channel files of revoked / unknown staff.
class StaffAggregationEngine {
  StaffAggregationEngine({required UnlockedVault vault, required CloudStore store, required SnapshotService snapshots})
      : _io = _ChannelIO(vault: vault, store: store, snapshots: snapshots),
        _keys = StaffChannelKeyStore(vault.db);

  final _ChannelIO _io;
  final StaffChannelKeyStore _keys;
  UnlockedVault get _v => _io.vault;
  VaultDatabase get _db => _io.db;

  Future<ChannelReport> run() async {
    final report = ChannelReport();
    if (!_v.isOwner) return report;
    await _migrateIfNeeded();

    final space = _io.store;
    if (space is! HouseholdCloudStore) {
      // No household space connected on this device: channels are not run
      // from here (never in the owner's own folder). Channel files found
      // there are from before the separation — stale; remove them.
      await purgeLegacyChannelFiles(space);
      return report;
    }

    final active = await _keys.active();
    // Folders to keep: active keys AND paired, unrevoked members (a member
    // whose key is being created right now must not lose its new folder).
    final keep = {
      for (final k in active) k.staffId.toLowerCase(),
      for (final r in await _db.select(
          'SELECT id FROM ${_db.qualified('staff_members', DataScope.shared)} WHERE revoked_at IS NULL AND deleted_at IS NULL'))
        (r['id']! as String).toLowerCase(),
    };
    // Folders to delete: ONLY ids this device KNOWS are revoked / removed
    // (or whose channel key was destroyed). An id merely missing from the
    // local staff_members may have been paired on another owner device
    // whose rows have not arrived yet — never delete those.
    final gone = <String>{
      for (final r in await _db.select(
          'SELECT id FROM ${_db.qualified('staff_members', DataScope.shared)} WHERE revoked_at IS NOT NULL OR deleted_at IS NOT NULL'))
        (r['id']! as String).toLowerCase(),
      for (final r in await _db.select('SELECT id FROM staff_channel_keys WHERE deleted_at IS NOT NULL'))
        (r['id']! as String).toLowerCase(),
    }..removeAll(keep);
    final seed = base64Decode((await _db.meta(OwnerMeta.ownerSigningSeed))!);
    try {
      await _runChannels(space, active, seed, report);
      // 3) Folders of revoked / removed staff: gone from the cloud (Google
      //    Drive and Dropbox / OneDrive delete a folder with its contents).
      try {
        for (final f in await space.staffFolders()) {
          if (!StaffChannel.isStaffId(f.name) || !gone.contains(f.name.toLowerCase())) continue;
          try {
            await space.deleteStaffFolder(f);
          } on CloudAuthExpired {
            rethrow;
          } catch (_) {}
        }
      } on CloudAuthExpired {
        rethrow;
      } catch (_) {
        // Listing failed (network): next pass.
      }
    } finally {
      wipe(seed);
    }
    return report;
  }

  Future<void> _runChannels(
    HouseholdCloudStore space,
    List<StaffChannelKey> active,
    Uint8List seed,
    ChannelReport report,
  ) async {
    for (final k in active) {
      final keys = await k.derive(_v.vaultId);
      try {
        // The member's sub-folder (re-created if someone deleted it: path
        // providers resume at once; on Google Drive the phone needs a
        // re-pair code, as its credentials carry the old folder id).
        final CloudStore folder;
        try {
          final found = await space.staffFolder(k.staffId, create: true);
          if (found == null) throw StateError('no folder');
          folder = found;
        } on CloudAuthExpired {
          rethrow;
        } catch (e) {
          report.rejected['staff_${k.staffId}/'] = SyncEngine.rejectReason(e);
          continue;
        }

        // 1) Aggregate this employee's entries.
        RemoteObject? f;
        try {
          f = await folder.stat(StaffChannel.staffFile(k.staffId));
        } on CloudAuthExpired {
          rethrow;
        } catch (e) {
          report.rejected[StaffChannel.staffFile(k.staffId)] = SyncEngine.rejectReason(e);
        }
        if (f != null) {
          try {
            final row = await _db.selectOne(
              'SELECT signing_key_b64, revoked_at FROM ${_db.qualified('staff_members', DataScope.shared)} WHERE id = ?',
              [k.staffId],
            );
            final signingKey = row?['signing_key_b64'];
            if (row == null || signingKey is! String) throw PackageTampered('unknown staff signer');
            if (row['revoked_at'] != null) throw PackageTampered('signer revoked');
            await _io.pull(
              from: folder,
              o: f,
              stateKey: 'chan:in:${k.staffId}',
              keys: keys,
              signerPublicKey: base64Decode(signingKey),
              expectedSigner: 'staff',
              expectedDeviceId: k.staffId,
              authority: PeerAuthority.staff,
              report: report,
            );
          } on PackageTampered catch (e) {
            report.rejected[f.name] = e.reason;
          } on SchemaTooNew catch (e) {
            report.rejected[f.name] = e.toString();
          } on CloudAuthExpired {
            rethrow;
          } catch (e) {
            // One unreadable staff file must not stop the other channels.
            report.rejected[f.name] = SyncEngine.rejectReason(e);
          }
        }

        // 2) Publish this employee's view (only if something changed).
        // Own try/catch: one failing view must not skip the other staff
        // members or the clean-up below.
        final outName = StaffChannel.ownerFile(k.staffId);
        try {
          final caps = await _capabilities(k.staffId);
          await _io.push(
            to: folder,
            name: outName,
            stateKey: 'chan:out:${k.staffId}',
            fingerprint: '${await _db.maxHlc(DataScope.shared)}|${k.generation}|${caps?.join(',') ?? '*'}',
            keys: keys,
            signingSeed: seed,
            signer: 'owner',
            build: () => _io.snapshots.exportPruned(
              _db,
              keys.sqlcipher,
              ChannelPruning.ownerView(k.staffId, vehicleIds: caps?.toSet()),
            ),
            report: report,
          );
        } on CloudAuthExpired {
          rethrow;
        } catch (e) {
          report.rejected[outName] = SyncEngine.rejectReason(e);
        }
      } finally {
        keys.wipeAll();
      }
    }
  }

  /// Create the channel for a NEW staff member (called while pairing):
  /// unique K_staff + the initial owner view file in the cloud, so the
  /// phone has its categories and cars on its very first sync.
  Future<StaffChannelKey> provision(String staffId) async {
    final k = await _keys.create(staffId);
    await run(); // migrates the vault to channels if needed, publishes S's view
    return k;
  }

  /// Household model → per-staff channels, once per vault:
  ///  * a unique K_staff for every active staff member (delivered through
  ///    the signed key-ring, encrypted to each phone's X25519 key);
  ///  * the household key K_shared is rotated and NOT given to staff, so
  ///    the owner's household snapshot is unreadable to every staff phone
  ///    from now on.
  Future<void> _migrateIfNeeded() => ensureStaffChannelMode(_db);

  /// Vehicles this staff member may log (null = all).
  Future<List<String>?> _capabilities(String staffId) async {
    final r = await _db.selectOne(
      'SELECT capabilities_json FROM ${_db.qualified('staff_members', DataScope.shared)} WHERE id = ?',
      [staffId],
    );
    final j = r == null ? null : jsonDecode(r['capabilities_json']! as String) as Map<String, dynamic>;
    final v = j?['vehicles'];
    // Empty list = all vehicles (StaffCapabilities.allowsVehicle).
    return v is List && v.isNotEmpty ? (List<String>.from(v)..sort()) : null;
  }
}

/// Household model → per-staff channels, once per vault (also called by
/// pairing BEFORE a new staff key exists, so the very first key-ring a new
/// phone sees is already the isolated one):
///  * a unique K_staff for every active staff member (delivered through
///    the signed key-ring, encrypted to each phone's X25519 key);
///  * the household key K_shared is rotated and NOT given to staff, so
///    the owner's household snapshot is unreadable to every staff phone
///    from now on.
Future<void> ensureStaffChannelMode(VaultDatabase db) async {
  if (await db.meta(StaffChannel.modeMetaKey) == '1') return;
  final keys = StaffChannelKeyStore(db);
  final staff = await db.select(
    'SELECT id FROM ${db.qualified('staff_members', DataScope.shared)} WHERE revoked_at IS NULL AND deleted_at IS NULL',
  );
  await db.transaction((tx) async {
    for (final s in staff) {
      final id = s['id']! as String;
      // Every read goes through `tx`: an outer-db call here deadlocks.
      if (await keys.keyFor(id, tx: tx) == null) await keys.create(id, tx: tx);
    }
    // New household epoch, owner devices only.
    final epoch = int.tryParse(await db.meta(OwnerMeta.householdEpoch, tx: tx) ?? '') ?? 1;
    final gen = await keys.currentGeneration(tx: tx);
    final next = (epoch > gen ? epoch : gen) + 1;
    await db.setMeta(OwnerMeta.householdKey(next), base64Encode(randomBytes(32)), tx: tx);
    await db.setMeta(OwnerMeta.householdEpoch, '$next', tx: tx);
    await db.setMeta(StaffChannel.modeMetaKey, '1', tx: tx);
  });
  // The sync engine adopts the new epoch on its next pass (ownerAdoptEpoch).
}

/// Old-format channel files (`staff_<id>.db`, `staff_<id>.owner.db`) in a
/// folder that is NOT a household space — the owner's own app folder, or a
/// household cloud connected before the separation. Nothing reads them any
/// more; best effort, never throws (except an expired sign-in).
Future<int> purgeLegacyChannelFiles(CloudStore store, {bool keyRing = false}) async {
  var n = 0;
  try {
    for (final o in await store.list(prefix: StaffChannel.prefix)) {
      if (StaffChannel.parse(o.name) == null) continue;
      try {
        await store.delete(o);
        n++;
      } on CloudAuthExpired {
        rethrow;
      } catch (_) {}
    }
    if (keyRing) {
      // Every ring name (legacy shared ring and per-owner-device rings).
      // Callers pass only stores that are NOT the household root.
      for (final o in await store.list(prefix: KeyRing.prefix)) {
        if (!KeyRing.isRingName(o.name)) continue;
        try {
          await store.delete(o);
          n++;
        } on CloudAuthExpired {
          rethrow;
        } catch (_) {}
      }
    }
  } on CloudAuthExpired {
    rethrow;
  } catch (_) {}
  return n;
}

// ======================================================================
// Staff: isolated client
// ======================================================================

/// Staff side. Touches exactly three cloud names — the key-ring (household
/// root, read by SyncEngine), its own `staff_<me>.db` and
/// `staff_<me>.owner.db` (its own sub-folder) — by exact name, never by
/// listing; holds only its own K_staff (as its "household" key). Runs ONLY
/// over a [HouseholdCloudStore]: a staff phone never writes anywhere else.
class StaffChannelClient {
  StaffChannelClient({required UnlockedVault vault, required CloudStore store, required SnapshotService snapshots})
      : _io = _ChannelIO(vault: vault, store: store, snapshots: snapshots);

  final _ChannelIO _io;
  UnlockedVault get _v => _io.vault;

  Future<ChannelReport> run() async {
    final report = ChannelReport();
    final creds = _v.staffCredentials!;
    final me = creds.staffId;
    final space = _io.store;
    final folder = space is HouseholdCloudStore ? await space.staffFolder(me) : null;
    if (folder == null) {
      // Old-format pairing (owner-app token) or no folder in the
      // credentials: nothing is read or written. The phone says "pair again".
      report.rejected[StaffChannel.staffFile(me)] = 'not paired to a household space';
      return report;
    }

    // One-time: drop other employees' rows left from the household model.
    if (await _v.db.meta(StaffChannel.modeMetaKey) != '1') {
      final sqls = ChannelPruning.purgeForeign(me);
      await _v.db.raw.rawQuery(sqls.first); // PRAGMA secure_delete — outside the transaction
      await _v.db.transaction((tx) async {
        for (final sql in sqls.skip(1)) {
          await tx.execute(sql);
        }
        await _v.db.setMeta(StaffChannel.modeMetaKey, '1', tx: tx);
      });
    }

    // 1) The owner's view for me.
    final view = await folder.stat(StaffChannel.ownerFile(me));
    if (view != null) {
      try {
        await _io.pull(
          from: folder,
          o: view,
          stateKey: 'chan:in:owner',
          keys: _v.sharedKeys, // derived from MY K_staff
          signerPublicKey: creds.ownerSigningKey,
          expectedSigner: 'owner',
          expectedDeviceId: null, // any owner device
          authority: PeerAuthority.owner,
          report: report,
        );
      } on PackageTampered catch (e) {
        report.rejected[view.name] = e.reason;
      } on SchemaTooNew catch (e) {
        report.rejected[view.name] = e.toString();
      } on CloudAuthExpired {
        rethrow;
      } catch (e) {
        // Unreadable owner view: still upload my own entries below.
        report.rejected[view.name] = SyncEngine.rejectReason(e);
      }
    }

    // 2) My own entries.
    await _io.push(
      to: folder,
      name: StaffChannel.staffFile(me),
      stateKey: 'chan:out:self',
      fingerprint: '${await _v.db.maxHlc(DataScope.shared)}|${_v.sharedKeys.epoch}',
      keys: _v.sharedKeys,
      signingSeed: creds.staffSigningSeed,
      signer: 'staff',
      build: () => _io.snapshots.exportPruned(_v.db, _v.sharedKeys.sqlcipher, ChannelPruning.staffUpload(me)),
      report: report,
    );
    return report;
  }
}

/// Fresh ids for staff profiles (kept here so the manager is self-contained).
String newStaffId() => newId();

/// HKDF-separated fingerprint of a channel key, safe to show in support
/// screens ("key 3F·9A·…") without revealing it.
Future<String> channelKeyFingerprint(Uint8List key) async {
  final h = await Sha256().hash(utf8.encode('qlv/staff-channel-fp|') + key);
  return h.bytes.take(4).map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join('·');
}
