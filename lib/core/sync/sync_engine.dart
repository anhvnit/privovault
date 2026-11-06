import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/aead.dart' show constantTimeEquals, wipe;
import '../crypto/vault_keys.dart';
import '../db/vault_database.dart';
import '../db/vault_database_service.dart';
import '../roles.dart';
import '../util/hlc.dart';
import 'cloud/cloud_store.dart';
import 'cloud/household_store.dart' show HouseholdAuthExpired;
import 'keyring.dart';
import 'merge_engine.dart';
import 'owner_key_state.dart';
import 'package_format.dart';
import 'snapshot.dart';
import 'staff_channel.dart';
import 'staff_revocation.dart';

/// Outcome of one sync pass (shown in Vault settings; never uploaded).
class SyncReport {
  final pulled = <String>[];
  final pushed = <String>[];
  final skippedUnchanged = <String>[];
  final rejected = <String, String>{}; // file → reason (tampered, wrong vault, revoked signer...)
  int conflicts = 0;

  /// Rows refused by the merge (staff authority / capabilities / bad HLC).
  int rowsRejected = 0;

  /// Rows postponed because their HLC is too far in the future.
  int rowsDeferred = 0;
  bool keyRotated = false;
  bool revoked = false;

  /// Staff: the owner replaced its identity keys (new Emergency Kit). This
  /// phone still trusts the old ones and must be paired again (UI: "pair
  /// again"). Nothing was changed locally.
  bool ownerIdentityChanged = false;

  /// Owner: another owner device declared THIS device lost. It no longer
  /// uploads anything (the others refuse and delete its packages).
  bool ownerDeviceRevoked = false;
  DateTime finishedAt = DateTime.now();
}

/// Hooks the engine needs from the session (role-specific side effects).
abstract class SyncHost {
  /// Staff: apply a newer household key found in the key-ring.
  Future<void> applyStaffKeyRotation(Uint8List householdKey, int epoch);

  /// Staff: this device was removed from the key-ring.
  Future<void> handleRevoked();

  /// Owner: private.db (merged from another owner device) names a newer
  /// household epoch than our open shared.db uses.
  Future<void> ownerAdoptEpoch(int epoch, Uint8List householdKey);
}

/// Deterministic BYOC sync.
///
/// Storage model: **single-writer files**. Each device only ever writes its
/// own `ql.<scope>.<deviceId>.qlv`, so two devices can never overwrite each
/// other in the cloud (no lost updates, no provider-side locking needed).
/// Every device reads everyone else's file and merges rows by HLC.
///
/// Decision table per peer file (no guessing, same result everywhere):
///
/// | remote version vs last merged | action                       |
/// |-------------------------------|------------------------------|
/// | equal (hash match)            | skip — nothing new           |
/// | different                     | download → verify signature  |
/// |                               | → decrypt → row-level merge  |
///
/// | local max HLC vs last pushed  | action                       |
/// |-------------------------------|------------------------------|
/// | equal and remote copy intact  | skip push                    |
/// | greater, or our file missing / altered (hash ≠ what we pushed) | snapshot → seal → upload |
///
/// Same-row concurrent edits are resolved by HLC and the losing version is
/// kept locally in `sync_conflicts` for the Secure Resolution UI.
class SyncEngine {
  SyncEngine({
    required this.vault,
    required this.store,
    required this.snapshots,
    required this.host,
    CloudStore? channelStore,
  }) : channelStore = channelStore ?? store;

  final UnlockedVault vault;

  /// The vault's home (owner devices' ql.* packages).
  final CloudStore store;

  /// Where the household channel lives: key-ring + staff_<id>(.owner).db.
  /// Same as [store] unless the owner's home can't be shared with staff
  /// (iCloud) and a separate household cloud was connected.
  final CloudStore channelStore;
  final SnapshotService snapshots;
  final SyncHost host;

  VaultDatabase get db => vault.db;
  MergeEngine get _merge => MergeEngine(db);

  static String fileName(DataScope s, String deviceId) => 'ql.${s.name}.$deviceId.qlv';

  static ({DataScope scope, String deviceId})? parseName(String name) {
    final m = RegExp(r'^ql\.(shared|private)\.([0-9a-fA-F-]{8,64})\.qlv$').firstMatch(name);
    if (m == null) return null;
    return (scope: DataScope.values.byName(m.group(1)!), deviceId: m.group(2)!);
  }

  Future<SyncReport> run() async {
    final report = SyncReport();
    // Locked mid-flight: keys are already wiped; never seal with them.
    if (vault.isDisposed) return report..finishedAt = DateTime.now();

    // Staff: key-rings first (rotation / revocation changes everything):
    // the only listing a staff phone makes, limited to `ql.keyring.*`
    // (one ring per owner device). Then the isolated channel, by exact name.
    if (!vault.isOwner) {
      final (ok, _) = await _staffKeyRing(report);
      if (!ok) return report..finishedAt = DateTime.now();
      // Always the isolated channel: a staff phone never lists or pushes
      // shared packages against the household root (legacy shared-key
      // pairings must pair again).
      final r = await StaffChannelClient(vault: vault, store: channelStore, snapshots: snapshots).run();
      report.pulled.addAll(r.pulled);
      report.pushed.addAll(r.pushed);
      report.rejected.addAll(r.rejected);
      report.conflicts += r.conflicts;
      report.rowsRejected += r.rowsRejected;
      report.rowsDeferred += r.rowsDeferred;
      return report..finishedAt = DateTime.now();
    }

    final remote = await store.list();
    final byName = {for (final o in remote) o.name: o};

    // Owner devices declared lost (OwnerKeyState): their packages are
    // neither merged nor kept. Refreshed once other owner devices'
    // private packages (which may carry new declarations) are merged.
    final keyState = OwnerKeyState(db);
    var lostOwners = vault.isOwner ? await keyState.revokedDevices() : const <String>{};

    // 2) Pull peers — private first, so an owner sees a rotated household
    //    epoch (from another owner device) before reading shared files.
    final ordered = [...remote]..sort((a, b) => (a.name.startsWith('ql.private.') ? 0 : 1).compareTo(b.name.startsWith('ql.private.') ? 0 : 1));
    var checkedEpoch = false;
    // Owner: after merging the other owner devices' private packages,
    // bring this device's key state in line (OwnerKeyState.reconcile:
    // household keys, channel mode, staff grants), then adopt the agreed
    // household key if the open shared.db is not under it — a newer epoch
    // (another owner device rotated, or a re-key a crash interrupted) or
    // the same epoch whose key lost the multi-device tie-break. Re-keys
    // first, then the scheduler re-runs with the new vault.
    Future<bool> adoptNewerEpoch() async {
      checkedEpoch = true;
      await keyState.reconcile();
      lostOwners = await keyState.revokedDevices();
      final e = int.parse((await db.meta(OwnerMeta.householdEpoch)) ?? '1');
      if (e < vault.sharedKeys.epoch) return false;
      final b64 = await db.meta(OwnerMeta.householdKey(e));
      if (b64 == null) return false;
      final hk = base64Decode(b64);
      try {
        if (e == vault.sharedKeys.epoch) {
          final agreed = await SharedKeys.derive(hk, vault.vaultId, e);
          final same = constantTimeEquals(agreed.sqlcipher, vault.sharedKeys.sqlcipher);
          agreed.wipeAll();
          if (same) return false;
        }
        await host.ownerAdoptEpoch(e, hk);
      } finally {
        wipe(hk); // the re-key keeps its own derived copies
      }
      report.keyRotated = true;
      return true;
    }

    for (final o in ordered) {
      if (vault.isOwner && !checkedEpoch && !o.name.startsWith('ql.private.')) {
        if (await adoptNewerEpoch()) return report..finishedAt = DateTime.now();
      }
      final n = parseName(o.name);
      if (n == null || n.deviceId == vault.deviceId) continue;
      if (n.scope == DataScope.private && !vault.isOwner) continue; // staff never even downloads it
      if (lostOwners.contains(n.deviceId.toLowerCase())) {
        report.rejected[o.name] = 'owner device declared lost';
        continue;
      }
      try {
        await _pull(o, n.scope, n.deviceId, report);
      } on PackageTampered catch (e) {
        report.rejected[o.name] = e.reason;
      } on SchemaTooNew catch (e) {
        report.rejected[o.name] = e.toString();
      } on CloudAuthExpired {
        rethrow; // the session is gone: stop and ask to sign in again
      } catch (e) {
        // One unreadable file (corrupt SQLite, wrong key, I/O) must not
        // stop the other peers from syncing. No contents in the reason.
        report.rejected[o.name] = rejectReason(e);
      }
    }

    // 3) Push our own files.
    if (vault.isDisposed) return report..finishedAt = DateTime.now();
    if (vault.isOwner && !checkedEpoch && await adoptNewerEpoch()) return report..finishedAt = DateTime.now();
    if (vault.isOwner && lostOwners.contains(vault.deviceId.toLowerCase())) {
      // Declared lost by another owner device: never upload again (they
      // would refuse it anyway). Local data is untouched.
      report.ownerDeviceRevoked = true;
      return report..finishedAt = DateTime.now();
    }
    var existingShared = byName[fileName(DataScope.shared, vault.deviceId)];
    if (vault.isOwner) {
      final ownPrivateName = fileName(DataScope.private, vault.deviceId);
      final ownSharedName = fileName(DataScope.shared, vault.deviceId);
      var existingPrivate = byName[ownPrivateName];
      var pushPrivate = true;
      // After a new Emergency Kit the master key (and owner identity)
      // changed: REPLACE our packages and key-ring so the provider keeps no
      // revision the previous recovery phrase could still open. Every copy
      // under our names goes (providers like Google Drive can hold several
      // files with one name), PERMANENTLY (Dropbox keeps deleted files,
      // OneDrive moves them to its recycle bin). Only push once every delete
      // is CONFIRMED: a put(existing: null) next to a surviving file would
      // create a duplicate on Drive. On failure the flag stays set and the
      // pushes wait for the next pass.
      final reencrypt = await vault.cloudReencryptPending();
      if (reencrypt) {
        final mine = [for (final o in remote) if (o.name == ownPrivateName || o.name == ownSharedName) o];
        try {
          for (final o in mine) {
            await store.deletePermanently(o);
          }
          try {
            final ring = await channelStore.stat(KeyRing.fileNameFor(vault.deviceId));
            if (ring != null) await channelStore.deletePermanently(ring);
          } on HouseholdAuthExpired {
            // Only the household sign-in expired: the vault's own packages
            // still go up now; _ownerKeyRing deletes the old ring for good
            // (before writing the new one) once signed in again.
            await _writeState(_ringPurgeState, const {'pending': true});
          }
          existingPrivate = null;
          existingShared = null;
          byName.remove(ownSharedName);
          await _writeState('pushed:${DataScope.private.name}', const <String, Object?>{});
          await _writeState('pushed:${DataScope.shared.name}', const <String, Object?>{});
          await _writeState('pushed:keyring', const <String, Object?>{});
        } on CloudAuthExpired {
          rethrow;
        } catch (_) {
          pushPrivate = false;
          report.rejected[ownPrivateName] = 'old package not yet removed';
        }
      }
      if (pushPrivate) await _push(DataScope.private, existingPrivate, report);
      if (reencrypt && !pushPrivate) {
        // Never re-upload shared data next to old revisions still in place.
        return report..finishedAt = DateTime.now();
      }
      if (reencrypt && report.pushed.contains(ownPrivateName)) {
        await vault.clearCloudReencryptPending();
      }
      await _purgeLostOwnerDevices(remote, lostOwners);
    }
    // If shared.db was recreated empty and our cloud copy is not merged
    // yet, pushing now would overwrite it with nothing: wait.
    final sharedSafe = !vault.isOwner || await _recoverRecreatedShared(byName, report);
    if (sharedSafe) await _push(DataScope.shared, existingShared, report);

    // 4) Owner: publish key-ring if it changed, then aggregate every
    //    staff member's isolated channel into this vault.
    if (vault.isOwner) {
      // Finish revocations whose steps failed earlier (idempotent).
      await StaffRevocation(db).resumePending();
      await _ownerKeyRing(report, lostOwners);
      final r = await StaffAggregationEngine(vault: vault, store: channelStore, snapshots: snapshots).run();
      report.pulled.addAll(r.pulled);
      report.pushed.addAll(r.pushed);
      report.rejected.addAll(r.rejected);
      report.conflicts += r.conflicts;
      report.rowsRejected += r.rowsRejected;
      report.rowsDeferred += r.rowsDeferred;
    }

    return report..finishedAt = DateTime.now();
  }

  // ================================================================ pull

  Future<void> _pull(RemoteObject o, DataScope scope, String peerId, SyncReport report) async {
    final stateKey = 'peer:${scope.name}:$peerId';
    final prev = await _readState(stateKey);
    if (unchangedSinceMerge(prev, o.version)) {
      report.skippedUnchanged.add(o.name);
      return;
    }
    // Legacy household file of a revoked staff member: it would be refused
    // after download anyway ("signer revoked"), so don't fetch it at all.
    if (scope == DataScope.shared && vault.isOwner && peerId != vault.deviceId) {
      final s = await db.selectOne(
          'SELECT revoked_at FROM ${db.qualified('staff_members', DataScope.shared)} WHERE id = ?', [peerId]);
      if (s != null && s['revoked_at'] != null) {
        report.rejected[o.name] = 'signer revoked';
        return;
      }
    }
    final sealed = SealedPackage.parse(await store.downloadCapped(o, CloudLimits.maxPackageBytes));
    final h = sealed.header;
    if (h.vaultId != vault.vaultId) throw PackageTampered('foreign vault');
    if (h.deviceId != peerId || h.scope != scope) throw PackageTampered('name/header mismatch');

    // Signer → verification key → authority.
    final PeerAuthority authority;
    if (h.signer == 'owner') {
      await sealed.verify(await _ownerSigningPublicKey());
      authority = PeerAuthority.owner;
    } else {
      if (scope == DataScope.private) throw PackageTampered('staff-signed private package');
      final staff = await db.selectOne(
          'SELECT signing_key_b64, revoked_at FROM ${db.qualified('staff_members', DataScope.shared)} WHERE id = ?',
          [peerId]);
      if (staff == null) throw PackageTampered('unknown staff signer');
      // Any package signed by a revoked key is refused: `created_at` is
      // chosen by the sender, so it cannot prove "written before revocation".
      if (staff['revoked_at'] != null) throw PackageTampered('signer revoked');
      final signingKey = staff['signing_key_b64'];
      if (signingKey is! String) throw PackageTampered('unknown staff signer');
      await sealed.verify(base64Decode(signingKey));
      authority = PeerAuthority.staff;
    }

    // Keys for this package. Shared packages: every key this vault knows
    // for that epoch (two owner devices may have created one each before
    // they agreed — see OwnerKeyState); the right one opens it.
    final options = <({Uint8List sync, Uint8List sqlcipher})>[];
    final derived = <SharedKeys>[]; // fresh copies, wiped below
    try {
      if (scope == DataScope.private) {
        options.add((sync: vault.privateKeys!.sync, sqlcipher: vault.privateKeys!.sqlcipher));
      } else {
        final channelKey = vault.isOwner && authority == PeerAuthority.staff ? await StaffChannelKeyStore(db).keyFor(peerId) : null;
        if (channelKey != null && channelKey.generation == h.keyEpoch) {
          // A phone on the previous app version, already moved to its own
          // channel key (it treats K_staff as its household key).
          final ck = await channelKey.derive(vault.vaultId);
          wipe(channelKey.key);
          derived.add(ck);
          options.add((sync: ck.sync, sqlcipher: ck.sqlcipher));
        } else {
          if (channelKey != null) wipe(channelKey.key);
          for (final sk in await _sharedKeysForEpoch(h.keyEpoch ?? 1)) {
            if (!identical(sk, vault.sharedKeys)) derived.add(sk);
            options.add((sync: sk.sync, sqlcipher: sk.sqlcipher));
          }
        }
      }
      if (options.isEmpty) {
        report.rejected[o.name] = 'unknown key epoch ${h.keyEpoch}';
        return;
      }

      PackageContents? contents;
      Uint8List? sqlKey;
      Object? lastError;
      for (final k in options) {
        try {
          contents = await sealed.open(k.sync);
          sqlKey = k.sqlcipher;
          break;
        } on PackageTampered catch (e) {
          lastError = e; // wrong key of this epoch: try the next one
        }
      }
      if (contents == null || sqlKey == null) throw lastError ?? PackageTampered('decryption failed');

      final staged = await snapshots.stage(contents.database, 'peer');
      try {
        final r = await _merge.merge(
          peerFile: staged,
          peerSqlcipherKey: sqlKey,
          scope: scope,
          peerDeviceId: peerId,
          authority: authority,
          baseHlc: (prev?['max_hlc'] as String?) ?? '',
        );
        report.conflicts += r.conflicts;
        report.rowsRejected += r.rejectedByAuthority;
        report.rowsDeferred += r.deferredFuture;
        await _writeState(stateKey, mergeState(o.version, r, prev));
        report.pulled.add(o.name);
      } finally {
        await snapshots.discard(staged);
      }
    } finally {
      for (final k in derived) {
        k.wipeAll();
      }
    }
  }

  /// Owner: shared.db had to be recreated empty at unlock
  /// ([OwnerMeta.sharedDbRecreated]). Merge this device's own cloud shared
  /// package back first. Returns true when pushing shared data is safe.
  Future<bool> _recoverRecreatedShared(Map<String, RemoteObject> byName, SyncReport report) async {
    if (await db.meta(OwnerMeta.sharedDbRecreated) == null) return true;
    final own = byName[fileName(DataScope.shared, vault.deviceId)];
    if (own != null) {
      try {
        await _pull(own, DataScope.shared, vault.deviceId, report);
      } on CloudAuthExpired {
        rethrow;
      } catch (e) {
        report.rejected[own.name] = rejectReason(e);
      }
      if (!report.pulled.contains(own.name) && !report.skippedUnchanged.contains(own.name)) return false;
    }
    final currency = await db.meta(OwnerMeta.baseCurrency);
    if (currency != null && await db.sharedMeta(SharedMeta.baseCurrency) == null) {
      await db.setSharedMeta(SharedMeta.baseCurrency, currency);
    }
    await db.execute('DELETE FROM main.vault_meta WHERE key = ?', [OwnerMeta.sharedDbRecreated], {'vault_meta'});
    return true;
  }

  /// Bookkeeping after a merge. The version is always recorded; rows
  /// deferred for a future HLC add `retry_after` (ms): the same file
  /// version is downloaded again only once the earliest deferred row has
  /// become acceptable (its time − [HlcClock.maxDriftMs]). An empty max HLC
  /// never erases the previous merge base.
  static Map<String, Object?> mergeState(String version, MergeReport r, Map<String, dynamic>? prev) {
    final deferredMs = r.deferredFuture > 0 ? HlcClock.decode(r.minDeferredHlc)?.ms : null;
    return {
      'version': version,
      'max_hlc': r.peerMaxHlc.isNotEmpty ? r.peerMaxHlc : (prev?['max_hlc'] as String? ?? ''),
      if (r.deferredFuture > 0)
        // Unknown time (should not happen): retry in max-drift from now.
        'retry_after': deferredMs != null
            ? deferredMs - HlcClock.maxDriftMs
            : DateTime.now().toUtc().millisecondsSinceEpoch + HlcClock.maxDriftMs,
    };
  }

  /// True when [version] was already merged and no deferred rows are due.
  static bool unchangedSinceMerge(Map<String, dynamic>? prev, String version) {
    if (prev == null || prev['version'] != version) return false;
    final retry = prev['retry_after'];
    return retry is! int || DateTime.now().toUtc().millisecondsSinceEpoch < retry;
  }

  /// Writes sync bookkeeping only when it changed: every `vault_meta` write
  /// notifies listeners, which would schedule yet another sync pass.
  static Future<void> writeStateIfChanged(VaultDatabase db, String key, Map<String, Object?> value) async {
    final encoded = jsonEncode(value);
    if (await db.meta('sync.$key') == encoded) return;
    await db.setMeta('sync.$key', encoded);
  }

  /// Short, content-free reason for [SyncReport.rejected].
  static String rejectReason(Object e) => switch (e) {
        PackageTampered(:final reason) => reason,
        SchemaTooNew() => e.toString(),
        FormatException() => 'malformed file',
        RemoteTooLarge() => 'file too large',
        _ => 'unreadable file',
      };

  // ================================================================ push

  Future<void> _push(DataScope scope, RemoteObject? existing, SyncReport report) async {
    final stateKey = 'pushed:${scope.name}';
    final prev = await _readState(stateKey);
    final localHlc = await db.maxHlc(scope);
    final epoch = vault.sharedKeys.epoch;
    // Same-epoch re-key (multi-device tie-break): the file must be re-sealed
    // even though epoch and rows are unchanged.
    final keyFp = scope == DataScope.shared ? await OwnerKeyState.fingerprint(vault.sharedKeys.root) : null;
    final intact = existing != null && existing.version == prev?['version'];
    if (intact &&
        prev?['hlc'] == localHlc &&
        (scope == DataScope.private || (prev?['epoch'] == epoch && prev?['kf'] == keyFp))) {
      return;
    }

    final isPrivate = scope == DataScope.private;
    final sqlKey = isPrivate ? vault.privateKeys!.sqlcipher : vault.sharedKeys.sqlcipher;
    final syncKey = isPrivate ? vault.privateKeys!.sync : vault.sharedKeys.sync;
    final dbBytes = await snapshots.export(db, scope, sqlKey);
    final behavior = isPrivate ? await vault.behaviorStore.readSealed() : null; // already AES-GCM sealed
    final wrappedMk = isPrivate ? await db.meta(OwnerMeta.recoveryWrappedMk) : null;

    // Fixed once: the header is built twice (AAD form, then signed form) and
    // both must be byte-identical apart from body_sha256.
    final createdAt = DateTime.now().toUtc().millisecondsSinceEpoch;
    final seed = await _signingSeed();
    final Uint8List bytes;
    try {
      bytes = await SealedPackage.build(
        header: (hash) => PackageHeader(
          scope: scope,
          vaultId: vault.vaultId,
          deviceId: vault.deviceId,
          signer: vault.isOwner ? 'owner' : 'staff',
          schemaVersion: isPrivate ? privoVaultSchema.privateVersion : privoVaultSchema.sharedVersion,
          createdAt: createdAt,
          maxHlc: localHlc,
          bodySha256: hash,
          keyEpoch: isPrivate ? null : epoch,
          wrappedMasterKey: wrappedMk,
        ),
        syncKey: syncKey,
        signingSeed: seed,
        database: dbBytes,
        behaviorSealed: behavior,
      );
    } finally {
      // Owner: a freshly decoded copy of the signing seed. Staff: the
      // session's own credentials, which must stay intact.
      if (vault.isOwner) wipe(seed);
    }
    final up = await store.put(fileName(scope, vault.deviceId), bytes, existing: existing);
    await _writeState(stateKey, {'version': up.version, 'hlc': localHlc, 'epoch': epoch, if (keyFp != null) 'kf': keyFp});
    report.pushed.add(up.name);
  }

  // ============================================================ key-ring

  /// Sync state: our pre-rotation key-ring still has to be deleted permanently.
  static const _ringPurgeState = 'keyring:purge-old';

  /// Upper bound on key-ring files a staff phone reads per pass.
  static const _maxRings = 32;

  /// Staff: (false, _) when the device was revoked or its key replaced
  /// (stop this pass); `isolated` = the owner uses per-staff channels.
  ///
  /// Every owner device writes its own `ql.keyring.<ownerDeviceId>.qlk`
  /// (plus the legacy shared name from older versions). Rules:
  ///  * listed as revoked in ANY valid ring → revoked (revocation is
  ///    monotonic and staff ids are never reused);
  ///  * rings written by an owner device that a valid ring declares lost
  ///    (`rod`) are ignored;
  ///  * the key comes from the newest valid ring that HAS an entry for this
  ///    phone (highest epoch, then highest HLC). A ring without an entry is
  ///    no longer read as "revoked": an owner device that has not merged
  ///    this pairing yet would otherwise wipe the phone;
  ///  * a ring signed by a key we don't trust but carrying a notice signed
  ///    by the key we do trust → the owner rotated its identity: nothing
  ///    from the cloud is trusted until this phone is paired again.
  Future<(bool, bool)> _staffKeyRing(SyncReport report) async {
    final creds = vault.staffCredentials!;
    final objects = [for (final o in await channelStore.list(prefix: KeyRing.prefix)) if (KeyRing.isRingName(o.name)) o];
    final rings = <(String, KeyRing)>[];
    var identityRotated = false;
    for (final o in objects.take(_maxRings)) {
      try {
        final r = await KeyRing.verify(
          await channelStore.downloadCapped(o, CloudLimits.maxKeyRingBytes),
          creds.ownerSigningKey,
          vaultId: vault.vaultId,
        );
        if (r.vaultId != vault.vaultId) continue;
        final named = KeyRing.writerOf(o.name);
        final w = r.writer;
        if (named != null && (w == null || w.toLowerCase() != named.toLowerCase())) {
          report.rejected[o.name] = 'key-ring name/writer mismatch';
          continue;
        }
        rings.add((o.name, r));
      } on CloudAuthExpired {
        rethrow;
      } on OwnerIdentityRotated {
        identityRotated = true;
        report.rejected[o.name] = 'owner keys changed';
      } catch (e) {
        // Forged / corrupt key-ring: same as no key-ring (keep current keys).
        report.rejected[o.name] = e is StateError ? 'key-ring signature invalid' : 'malformed key-ring';
      }
    }
    if (identityRotated) {
      // Rings still verifying under the old key are stale or forged (the
      // old key may be the leaked one): act on none of them.
      report.ownerIdentityChanged = true;
      return (false, false); // stop this pass: nothing is trusted until re-paired
    }
    if (rings.isEmpty) return (true, false); // owner hasn't published one yet

    final lost = {
      for (final r in rings)
        for (final d in r.$2.revokedOwners) d.toLowerCase(),
    };
    final usable = [
      for (final r in rings)
        if (r.$2.writer == null || !lost.contains(r.$2.writer!.toLowerCase())) r.$2,
    ];
    final isolated = usable.any((r) => r.isolated);
    if (usable.any((r) => r.revoked.contains(creds.staffId))) {
      report.revoked = true;
      await host.handleRevoked();
      return (false, isolated);
    }
    final mine = [for (final r in usable) if (r.entries.containsKey(creds.staffId)) r]..sort(KeyRing.compareNewest);
    if (mine.isEmpty) return (true, isolated);
    final best = mine.first;
    if (best.epoch < creds.keyEpoch) return (true, isolated);
    Uint8List? k;
    try {
      k = await best.householdKeyFor(
        staffId: creds.staffId,
        staffX25519Secret: creds.staffSecretKey,
        ownerX25519Public: creds.ownerPublicKey,
      );
    } catch (_) {
      k = null; // unreadable entry: keep the current key
    }
    if (k == null) return (true, isolated);
    if (best.epoch == creds.keyEpoch && constantTimeEquals(k, creds.householdKey)) {
      wipe(k);
      return (true, isolated);
    }
    // Newer epoch, or the same epoch with the key the owner devices agreed
    // on. The new credentials keep [k] (not wiped).
    await host.applyStaffKeyRotation(k, best.epoch);
    report.keyRotated = true;
    return (false, isolated); // vault object replaced; scheduler re-runs with new keys
  }

  /// Owner: publish THIS device's key-ring (`ql.keyring.<deviceId>.qlk`)
  /// when its content changed. Single writer per file, so two owner
  /// devices never overwrite each other.
  Future<void> _ownerKeyRing(SyncReport report, Set<String> lostOwners) async {
    final name = KeyRing.fileNameFor(vault.deviceId);
    var existing = await channelStore.stat(name);
    // Old-identity ring a new Emergency Kit could not delete earlier
    // (household sign-in had expired): remove it permanently, then write anew.
    if ((await _readState(_ringPurgeState))?['pending'] == true) {
      if (existing != null) await channelStore.deletePermanently(existing);
      existing = null;
      await _writeState(_ringPurgeState, const {'pending': false});
    }
    final epoch = vault.sharedKeys.epoch;
    final staff = await db.select(
        'SELECT id, public_key_b64, revoked_at FROM ${db.qualified('staff_members', DataScope.shared)} WHERE deleted_at IS NULL');
    final active = {
      for (final s in staff.where((s) => s['revoked_at'] == null)) s['id']! as String: base64Decode(s['public_key_b64']! as String),
    };
    final revoked = [for (final s in staff.where((s) => s['revoked_at'] != null)) s['id']! as String]..sort();
    final rod = lostOwners.toList()..sort();
    // Per-staff channels: each entry carries that staff member's own key,
    // under the channel key generation (not the owner's household epoch).
    final channels = await db.meta(StaffChannel.modeMetaKey) == '1';
    final keyStore = StaffChannelKeyStore(db);
    final perStaff = channels ? {for (final k in await keyStore.active()) k.staffId: k.key} : null;
    final ringEpoch = channels ? await keyStore.currentGeneration() : epoch;
    final notices = <String>[];
    try {
      final j = jsonDecode(await db.meta(OwnerMeta.ownerIdentityNotices) ?? '[]');
      if (j is List) notices.addAll(j.whereType<String>());
    } catch (_) {}

    final hk = base64Decode((await db.meta(OwnerMeta.householdKey(epoch)))!);
    final sk = base64Decode((await db.meta(OwnerMeta.ownerSecretKey))!);
    final seed = await _signingSeed();
    final String fingerprint;
    final Uint8List bytes;
    try {
      // Key fingerprints too: a changed K_staff / household key (devices
      // agreeing on one after a race) or a new owner identity republishes.
      fingerprint = jsonEncode({
        'e': ringEpoch,
        'a': (active.keys.toList()..sort()),
        'r': revoked,
        'iso': channels,
        if (perStaff != null)
          'k': {for (final id in (perStaff.keys.toList()..sort())) id: await OwnerKeyState.fingerprint(perStaff[id]!)},
        if (perStaff == null) 'hk': await OwnerKeyState.fingerprint(hk),
        'id': await OwnerKeyState.fingerprint(seed),
        'rod': rod,
        'n': notices.length,
      });
      final prev = await _readState('pushed:keyring');
      if (existing != null && prev?['fp'] == fingerprint && prev?['version'] == existing.version) return;

      bytes = await KeyRing.build(
        vaultId: vault.vaultId,
        epoch: ringEpoch,
        householdKey: hk,
        ownerX25519Secret: sk,
        ownerSigningSeed: seed,
        activeStaffPublicKeys: active,
        revoked: revoked,
        perStaffKeys: perStaff,
        writerDeviceId: vault.deviceId,
        hlc: db.clock.now(),
        revokedOwnerDevices: rod,
        identityNotices: notices,
      );
    } finally {
      // Decoded copies of owner secrets: zero them once the ring is built.
      wipe(hk);
      wipe(sk);
      wipe(seed);
      if (perStaff != null) {
        for (final k in perStaff.values) {
          wipe(k);
        }
      }
    }
    final up = await channelStore.put(name, bytes, existing: existing);
    await _writeState('pushed:keyring', {'fp': fingerprint, 'version': up.version});
    report.pushed.add(name);

    // The legacy shared ring (older versions: one file for every owner
    // device) is superseded by ours; staff would otherwise keep reading it.
    try {
      final legacy = await channelStore.stat(KeyRing.legacyFileName);
      if (legacy != null) await channelStore.deletePermanently(legacy);
    } on CloudAuthExpired {
      rethrow;
    } catch (_) {}

    // Remove revoked staff devices' files from the household folder.
    final names = {for (final id in revoked) fileName(DataScope.shared, id)};
    for (final o in await store.list()) {
      if (names.contains(o.name)) await store.delete(o);
    }
  }

  /// Owner: packages and key-rings of owner devices declared lost are
  /// deleted for good (best effort, retried every pass while any is left).
  Future<void> _purgeLostOwnerDevices(List<RemoteObject> remote, Set<String> lost) async {
    if (lost.isEmpty) return;
    for (final o in remote) {
      final n = parseName(o.name);
      if (n == null || !lost.contains(n.deviceId.toLowerCase())) continue;
      try {
        await store.deletePermanently(o);
      } on CloudAuthExpired {
        rethrow;
      } catch (_) {}
    }
    for (final id in lost) {
      final stateKey = 'lost-ring:$id';
      if ((await _readState(stateKey))?['done'] == true) continue;
      try {
        final ring = await channelStore.stat(KeyRing.fileNameFor(id));
        if (ring != null) await channelStore.deletePermanently(ring);
        await _writeState(stateKey, const {'done': true});
      } on HouseholdAuthExpired {
        return; // household sign-in expired: retried next pass; never stop the shared push
      } on CloudAuthExpired {
        rethrow;
      } catch (_) {}
    }
  }

  // ============================================================= helpers

  Future<Uint8List> _signingSeed() async => vault.isOwner
      ? base64Decode((await db.meta(OwnerMeta.ownerSigningSeed))!)
      : vault.staffCredentials!.staffSigningSeed;

  Future<List<int>> _ownerSigningPublicKey() async {
    if (!vault.isOwner) return vault.staffCredentials!.ownerSigningKey;
    final seed = await _signingSeed();
    try {
      final kp = await Ed25519().newKeyPairFromSeed(seed);
      return List<int>.of((await kp.extractPublicKey()).bytes);
    } finally {
      wipe(seed);
    }
  }

  /// Owner keeps every epoch's household key (to read stale staff files),
  /// including keys of an epoch that lost a multi-device tie-break; staff
  /// only holds the current one. Entries other than [UnlockedVault.sharedKeys]
  /// are fresh derivations the caller must wipe.
  Future<List<SharedKeys>> _sharedKeysForEpoch(int epoch) async {
    final out = <SharedKeys>[];
    final current = epoch == vault.sharedKeys.epoch;
    if (current) out.add(vault.sharedKeys);
    if (!vault.isOwner) return out;
    for (final k in await OwnerKeyState(db).householdKeys(epoch)) {
      try {
        final sk = await SharedKeys.derive(k, vault.vaultId, epoch);
        if (current && constantTimeEquals(sk.sqlcipher, vault.sharedKeys.sqlcipher)) {
          sk.wipeAll(); // the session's own key, already first
        } else {
          out.add(sk);
        }
      } finally {
        wipe(k);
      }
    }
    return out;
  }

  Future<Map<String, dynamic>?> _readState(String key) async {
    final v = await db.meta('sync.$key');
    return v == null ? null : jsonDecode(v) as Map<String, dynamic>;
  }

  Future<void> _writeState(String key, Map<String, Object?> value) => writeStateIfChanged(db, key, value);
}

/// Pairs the engine with the role check used by callers.
extension SyncRole on UnlockedVault {
  bool get syncsPrivate => role == AppRole.owner;
}
