import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:sqflite_sqlcipher/sqflite.dart' show Database;

import '../biometric/key_release.dart';
import '../db/ids.dart';
import '../db/vault_database.dart';
import '../db/vault_schema.dart';
import '../primitives/aead.dart';
import '../primitives/encrypted_json_store.dart';
import '../primitives/keys.dart';
import '../primitives/recovery.dart';
import 'crypto_meta.dart';
import 'vault_paths.dart';

/// Hook to write application data inside the creation transaction
/// (e.g. base currency, default categories).
typedef VaultSeed = Future<void> Function(VaultDatabase db, VaultExecutor tx);

/// An unlocked owner vault: private.db (main) + shared.db (attached).
class OwnerSession {
  OwnerSession({required this.db, required this.header, required this.privateKeys, required this.sharedKeys});

  final VaultDatabase db;
  final VaultHeader header;
  final VaultKeys privateKeys;
  final SharedKeys sharedKeys;

  /// AES-GCM key for the app's encrypted behaviour profile.
  Uint8List get behaviorKey => privateKeys.behavior;

  Future<void> close() async {
    await db.close();
    privateKeys.wipeAll();
    sharedKeys.wipeAll();
  }
}

/// An unlocked staff device: shared.db only.
class StaffSession {
  StaffSession({
    required this.db,
    required this.header,
    required this.sharedKeys,
    required this.credentials,
    required this.behaviorKey,
  });

  final VaultDatabase db;
  final VaultHeader header;
  final SharedKeys sharedKeys;

  /// The decrypted staff credential document (see [StaffCredentialFields]);
  /// the application owns every other field in it.
  final Map<String, dynamic> credentials;

  final Uint8List behaviorKey;

  Future<void> close() async {
    await db.close();
    sharedKeys.wipeAll();
    wipe(behaviorKey);
  }
}

/// Fields the handshake reads from a staff credential document.
abstract final class StaffCredentialFields {
  static const vaultId = 'vault_id';
  static const staffId = 'staff_id';
  static const householdKey = 'k_shared'; // base64, 32 bytes
  static const epoch = 'epoch';
}

/// The biometric ↔ secure hardware ↔ SQLCipher handshake, end to end.
///
/// ```
///  Face ID / BiometricPrompt
///        │  KeyRelease (hardware-bound by default; local_auth optional)
///        ▼
///  Master Key (32 B; wiped right after derivation)
///        │  HKDF-SHA256(salt = vaultId)
///        ├──► VaultKeys.sqlcipher ──► PRAGMA key           private.db
///        ├──► VaultKeys.behavior  ──► AES-GCM JSON store
///        ├──► VaultKeys.sync      ──► app's sync packages
///        └──► private.db › household_key_e<epoch>
///                   │ HKDF
///                   ├──► SharedKeys.sqlcipher ──► ATTACH shared.db KEY
///                   └──► SharedKeys.sync
/// ```
/// Staff devices: their own hardware master key only unlocks the encrypted
/// credential document that carries the household key from the owner.
///
/// No UI, no strings of its own (prompts are injected), no app tables
/// (schema is injected).
class VaultHandshake {
  VaultHandshake({
    required this.paths,
    required this.keyRelease,
    required this.schema,
    UnlockPrompts Function()? prompts,
  }) : _prompts = prompts ?? (() => UnlockPrompts.english);

  final VaultPaths paths;
  final KeyRelease keyRelease;
  final VaultSchema schema;
  final UnlockPrompts Function() _prompts;

  Future<VaultHeader?> header() => paths.readHeader();

  // ================================================================ owner

  /// First-run owner setup. Returns the session and the 12-word recovery
  /// phrase (show once; never persist it).
  Future<({OwnerSession session, String recoveryPhrase})> createOwnerVault({VaultSeed? seed}) async {
    final vaultId = newId();
    final deviceId = newId();
    await keyRelease.excludeFromBackup(paths.dir.path);
    final mk = await keyRelease.createMasterKey(reason: _prompts().createVault);
    try {
      final priv = await VaultKeys.derive(mk, vaultId);
      final householdKey = randomBytes(32);
      final shared = await SharedKeys.derive(householdKey, vaultId, 1);
      final ownerKp = await X25519().newKeyPair();
      final ownerSk = Uint8List.fromList(await ownerKp.extractPrivateKeyBytes());
      final ownerPk = (await ownerKp.extractPublicKey()).bytes;
      final signKp = await Ed25519().newKeyPair();
      final signSeed = Uint8List.fromList(await signKp.extractPrivateKeyBytes());
      final signPk = (await signKp.extractPublicKey()).bytes;
      final phrase = RecoveryPhrase.generate();
      final wrappedMk = await RecoveryPhrase.wrapMasterKey(mk, phrase, vaultId);

      final db = await VaultDatabase.open(
        sharedPath: paths.sharedDb,
        sharedKey: shared.sqlcipher,
        privatePath: paths.privateDb,
        privateKey: priv.sqlcipher,
        nodeId: deviceId,
        schema: schema,
      );
      await db.transaction((tx) async {
        await db.setMeta(CryptoMeta.householdEpoch, '1', tx: tx);
        await db.setMeta(CryptoMeta.householdKey(1), base64Encode(householdKey), tx: tx);
        await db.setMeta(CryptoMeta.ownerSecretKey, base64Encode(ownerSk), tx: tx);
        await db.setMeta(CryptoMeta.ownerSigningSeed, base64Encode(signSeed), tx: tx);
        await db.setMeta(CryptoMeta.recoveryWrappedMk, wrappedMk, tx: tx);
        await db.setSharedMeta(SharedCryptoMeta.ownerPublicKey, base64Encode(ownerPk), tx: tx);
        await db.setSharedMeta(SharedCryptoMeta.ownerSigningKey, base64Encode(signPk), tx: tx);
        await db.setSharedMeta(SharedCryptoMeta.vaultId, vaultId, tx: tx);
        if (seed != null) await seed(db, tx);
      });
      wipe(householdKey);
      wipe(ownerSk);
      wipe(signSeed);

      final h = VaultHeader(
        vaultId: vaultId,
        deviceId: deviceId,
        role: 'owner',
        createdAt: DateTime.now().millisecondsSinceEpoch,
      );
      await paths.writeHeader(h);
      return (
        session: OwnerSession(db: db, header: h, privateKeys: priv, sharedKeys: shared),
        recoveryPhrase: phrase,
      );
    } finally {
      wipe(mk);
    }
  }

  // =============================================================== unlock

  /// Biometric unlock for whichever role this device holds. Returns an
  /// [OwnerSession] or a [StaffSession]. Throws [VaultKeyException]
  /// (cancelled / lockout / invalidated …), [VaultWrongKey] or
  /// [VaultCipherUnavailable].
  Future<Object> unlock() async {
    final h = await paths.readHeader();
    if (h == null) throw StateError('No vault on this device');
    final owner = h.role == 'owner';
    final mk = await keyRelease.unlockMasterKey(reason: owner ? _prompts().unlockOwner : _prompts().unlockStaff);
    try {
      return owner ? await _openOwner(h, mk) : await _openStaff(h, mk);
    } finally {
      wipe(mk);
    }
  }

  Future<OwnerSession> _openOwner(VaultHeader h, Uint8List mk) async {
    final priv = await VaultKeys.derive(mk, h.vaultId);
    try {
      // Finish (or discard) a master-key rotation a crash interrupted.
      await _settlePendingOwnerRotation(priv);
      // Read the current household key from private.db before attaching shared.db.
      final raw = await VaultDatabase.openKeyed(paths.privateDb, priv.sqlcipher, readOnly: true);
      final Map<String, String> m;
      try {
        m = {
          for (final r in await raw.rawQuery('SELECT key, value FROM vault_meta')) r['key']! as String: r['value']! as String,
        };
      } finally {
        await raw.close();
      }
      // Did the last Emergency-Kit rotation really take? (iOS slot revert.)
      await _checkKitRotationFlag(m[CryptoMeta.recoveryWrappedMk]);
      final epoch = int.parse(m[CryptoMeta.householdEpoch]!);
      final shared = await _settleOwnerShared(h, m, epoch);
      final recreated = shared == null;
      final keys = shared ?? await _sharedKeysFromMeta(h, m, epoch);

      try {
        final db = await VaultDatabase.open(
          sharedPath: paths.sharedDb,
          sharedKey: keys.sqlcipher,
          privatePath: paths.privateDb,
          privateKey: priv.sqlcipher,
          nodeId: h.deviceId,
          schema: schema,
        );
        if (recreated) {
          try {
            await _reseedRecreatedShared(db, h, m);
          } catch (_) {
            await db.close();
            rethrow;
          }
        }
        return OwnerSession(db: db, header: h, privateKeys: priv, sharedKeys: keys);
      } catch (_) {
        keys.wipeAll();
        rethrow;
      }
    } catch (_) {
      priv.wipeAll();
      rethrow;
    }
  }

  Future<SharedKeys> _sharedKeysFromMeta(VaultHeader h, Map<String, String> m, int epoch) =>
      _sharedKeysFromB64(h, m[CryptoMeta.householdKey(epoch)]!, epoch);

  Future<SharedKeys> _sharedKeysFromB64(VaultHeader h, String b64, int epoch) async {
    final hk = base64Decode(b64);
    try {
      return await SharedKeys.derive(hk, h.vaultId, epoch);
    } finally {
      wipe(hk);
    }
  }

  /// Every household key in [m] other than the current epoch's agreed one:
  /// newest epoch first; per epoch the agreed key, then its alternatives.
  static List<({int epoch, String b64})> _fallbackHouseholdKeys(Map<String, String> m, int epoch) {
    final out = <({int epoch, String b64})>[];
    for (var e = epoch; e >= 1; e--) {
      final primary = m[CryptoMeta.householdKey(e)];
      if (e < epoch && primary != null) out.add((epoch: e, b64: primary));
      final altPrefix = '${CryptoMeta.householdKey(e)}_alt_';
      final alts = [for (final k in m.keys) if (k.startsWith(altPrefix)) k]..sort();
      for (final k in alts) {
        out.add((epoch: e, b64: m[k]!));
      }
    }
    return out;
  }

  /// Owner unlock: make sure shared.db is the right file under a key we
  /// hold, recovering from an interrupted household re-key. Returns the
  /// keys that open it, or null when shared.db does not exist at all (the
  /// caller opens a fresh one and flags it, see [CryptoMeta.sharedDbRecreated]).
  ///
  ///  * current epoch opens shared.db → done (a leftover `.rekey` is stale);
  ///  * `.rekey` opens with the current epoch → the swap was interrupted
  ///    after the export: promote it (atomic rename);
  ///  * else an OLDER epoch opens shared.db → the new epoch was committed in
  ///    private.db but the re-key never ran: open with that epoch; the sync
  ///    engine sees `household_epoch` > session epoch and re-runs the re-key.
  /// If nothing opens, falls through to the current epoch (→ VaultWrongKey).
  Future<SharedKeys?> _settleOwnerShared(VaultHeader h, Map<String, String> m, int epoch) async {
    final pending = File('${paths.sharedDb}.rekey');
    final current = await _sharedKeysFromMeta(h, m, epoch);
    var keep = false;
    try {
      if (await _opensWith(paths.sharedDb, current.sqlcipher)) {
        await _discardPendingShared();
        keep = true;
        return current;
      }
      if (await _pendingSharedComplete(pending.path, current.sqlcipher)) {
        await _promotePendingShared();
        keep = true;
        return current;
      }
      if (await File(paths.sharedDb).exists()) {
        // Older epochs, plus keys of a generation that lost a multi-device
        // tie-break ([CryptoMeta.householdKeyAlt]): a re-key to the agreed
        // key may have been interrupted. The sync engine sees the session
        // key differ from the agreed one and re-keys again.
        for (final c in _fallbackHouseholdKeys(m, epoch)) {
          final SharedKeys k;
          try {
            k = await _sharedKeysFromB64(h, c.b64, c.epoch);
          } catch (_) {
            continue; // malformed entry: never block the unlock on it
          }
          if (await _opensWith(paths.sharedDb, k.sqlcipher)) return k;
          k.wipeAll();
        }
        keep = true;
        return current; // nothing opens: let the normal open report VaultWrongKey
      }
      return null; // shared.db is gone
    } finally {
      if (!keep) current.wipeAll();
    }
  }

  /// shared.db was missing and has just been created empty. Restore the
  /// public crypto values staff/sync rely on (all derivable from private.db)
  /// and flag the vault so the next sync merges its cloud copy first.
  Future<void> _reseedRecreatedShared(VaultDatabase db, VaultHeader h, Map<String, String> m) async {
    final sk = m[CryptoMeta.ownerSecretKey];
    final seed = m[CryptoMeta.ownerSigningSeed];
    await db.transaction((tx) async {
      if (sk != null) {
        final kp = await X25519().newKeyPairFromSeed(base64Decode(sk));
        await db.setSharedMeta(SharedCryptoMeta.ownerPublicKey, base64Encode((await kp.extractPublicKey()).bytes), tx: tx);
      }
      if (seed != null) {
        final kp = await Ed25519().newKeyPairFromSeed(base64Decode(seed));
        await db.setSharedMeta(SharedCryptoMeta.ownerSigningKey, base64Encode((await kp.extractPublicKey()).bytes), tx: tx);
      }
      await db.setSharedMeta(SharedCryptoMeta.vaultId, h.vaultId, tx: tx);
      await db.setMeta(CryptoMeta.sharedDbRecreated, '${DateTime.now().toUtc().millisecondsSinceEpoch}', tx: tx);
    });
  }

  /// Atomic swap of `shared.db.rekey` over shared.db (POSIX rename replaces
  /// the target; there is never a moment without a complete shared.db).
  Future<void> _promotePendingShared() async {
    final tmp = File('${paths.sharedDb}.rekey');
    for (final suffix in ['-wal', '-shm', '-journal']) {
      await _deleteIfExists(File('${paths.sharedDb}$suffix'));
      await _deleteIfExists(File('${tmp.path}$suffix'));
    }
    await tmp.rename(paths.sharedDb);
  }

  Future<void> _discardPendingShared() async {
    for (final suffix in ['', '-journal', '-wal', '-shm']) {
      await _deleteIfExists(File('${paths.sharedDb}.rekey$suffix'));
    }
  }

  Future<StaffSession> _openStaff(VaultHeader h, Uint8List deviceMk) async {
    final dk = await StaffDeviceKeys.derive(deviceMk, h.deviceId);
    try {
      // Finish (or discard) a household key rotation a crash interrupted.
      await _settlePendingStaffCredentials(dk);
      final creds = await _credsStore(dk).load();
      final hk = base64Decode(creds[StaffCredentialFields.householdKey] as String);
      final shared = await SharedKeys.derive(
        hk,
        creds[StaffCredentialFields.vaultId] as String,
        creds[StaffCredentialFields.epoch] as int,
      );
      wipe(hk);
      final db = await VaultDatabase.open(
        sharedPath: paths.sharedDb,
        sharedKey: shared.sqlcipher,
        nodeId: h.deviceId,
        schema: schema,
      );
      return StaffSession(
        db: db,
        header: h,
        sharedKeys: shared,
        credentials: creds,
        behaviorKey: Uint8List.fromList(dk.behavior),
      );
    } finally {
      dk.wipeAll();
    }
  }

  // ================================================================ staff

  /// Pairing finished: create this device's own hardware key, store the
  /// credential document encrypted under it, open shared.db.
  Future<StaffSession> adoptStaffCredentials(Map<String, dynamic> credentials, {VaultSeed? seed}) async {
    final staffId = credentials[StaffCredentialFields.staffId] as String;
    final vaultId = credentials[StaffCredentialFields.vaultId] as String;
    await keyRelease.excludeFromBackup(paths.dir.path);
    final mk = await keyRelease.createMasterKey(reason: _prompts().secureDevice);
    try {
      final dk = await StaffDeviceKeys.derive(mk, staffId);
      await _credsStore(dk).save(credentials);
      dk.wipeAll();
      final h = VaultHeader(
        vaultId: vaultId,
        deviceId: staffId,
        role: 'staff',
        createdAt: DateTime.now().millisecondsSinceEpoch,
      );
      await paths.writeHeader(h);
      final session = await _openStaff(h, mk);
      if (seed != null) await session.db.transaction((tx) => seed(session.db, tx));
      return session;
    } finally {
      wipe(mk);
    }
  }

  /// Staff: re-key local shared.db to a newer household epoch and persist
  /// [updatedCredentials] (which must already carry the new key + epoch).
  ///
  /// Order matters (the DB key and the stored credentials must never
  /// disagree):
  ///  1. biometric release of the device key — cancelling Face ID here
  ///     changes nothing;
  ///  2. new credentials sealed into the PENDING slot;
  ///  3. `PRAGMA rekey` (transactional; on failure the pending slot is
  ///     deleted and both DB and credentials stay on the old key);
  ///  4. pending slot renamed over the live credentials (commit).
  /// A crash between 3 and 4 is settled at the next unlock
  /// ([_settlePendingStaffCredentials]).
  Future<SharedKeys> applyStaffKeyRotation({
    required VaultDatabase db,
    required VaultHeader header,
    required SharedKeys current,
    required Map<String, dynamic> updatedCredentials,
  }) async {
    final hk = base64Decode(updatedCredentials[StaffCredentialFields.householdKey] as String);
    final next = await SharedKeys.derive(hk, header.vaultId, updatedCredentials[StaffCredentialFields.epoch] as int);
    wipe(hk);
    try {
      final mk = await keyRelease.unlockMasterKey(reason: _prompts().applyKeyUpdate);
      try {
        final dk = await StaffDeviceKeys.derive(mk, header.deviceId);
        try {
          final pending = _pendingCredsStore(dk);
          await pending.save(updatedCredentials);
          try {
            await db.checkpoint();
            await db.raw.rawQuery('PRAGMA rekey = "${rawKeyLiteral(next.sqlcipher)}"');
          } catch (_) {
            await _deleteIfExists(pending.file); // roll back: old key + old creds
            rethrow;
          }
          await pending.file.rename(paths.staffCredentials.path);
        } finally {
          dk.wipeAll();
        }
      } finally {
        wipe(mk);
      }
    } catch (_) {
      next.wipeAll();
      rethrow;
    }
    current.wipeAll();
    return next;
  }

  /// Staff: persist [updatedCredentials] with the SAME household key and
  /// epoch (e.g. the owner moved the household to another cloud and sent a
  /// new cloud grant). No re-key; local data is untouched.
  Future<void> updateStaffCredentials({
    required VaultHeader header,
    required Map<String, dynamic> updatedCredentials,
  }) async {
    final mk = await keyRelease.unlockMasterKey(reason: _prompts().applyKeyUpdate);
    try {
      final dk = await StaffDeviceKeys.derive(mk, header.deviceId);
      await _credsStore(dk).save(updatedCredentials);
      dk.wipeAll();
    } finally {
      wipe(mk);
    }
  }

  // ============================================== owner: household epoch

  /// Owner: move shared.db to a new household key (after revoking staff, or
  /// when another owner device rotated). Exports into a fresh file under the
  /// new key, swaps files, reopens. [db] is closed; use the returned one.
  Future<({VaultDatabase db, SharedKeys sharedKeys})> rekeyOwnerShared({
    required VaultDatabase db,
    required VaultHeader header,
    required VaultKeys privateKeys,
    required SharedKeys current,
    required int epoch,
    required Uint8List householdKey,
  }) async {
    if (!db.hasPrivate) throw StateError('rekeyOwnerShared requires an owner connection');
    final next = await SharedKeys.derive(householdKey, header.vaultId, epoch);
    final tmp = File('${paths.sharedDb}.rekey');
    try {
      await _discardPendingShared();
      var mark = await _exportShared(db, tmp.path, next.sqlcipher);
      // A write that reaches shared.db after the export (a merge, a save on
      // another screen) would be lost by the swap: export again until the
      // connection's change counter is stable (bounded).
      for (var i = 0; i < _maxCatchUp && await _totalChanges(db) != mark; i++) {
        await _discardPendingShared();
        mark = await _exportShared(db, tmp.path, next.sqlcipher);
      }
    } catch (_) {
      next.wipeAll();
      try {
        await _discardPendingShared();
      } catch (_) {}
      rethrow; // nothing changed: [db] and [current] are still valid
    }
    await db.close(); // last connection: SQLite checkpoints the WAL into shared.db
    // Never delete shared.db itself: rename the complete new file over it.
    // A crash before the rename leaves old shared.db + shared.db.rekey, which
    // the next unlock settles ([_settleOwnerShared]).
    await _promotePendingShared();

    final VaultDatabase reopened;
    try {
      reopened = await VaultDatabase.open(
        sharedPath: paths.sharedDb,
        sharedKey: next.sqlcipher,
        privatePath: paths.privateDb,
        privateKey: privateKeys.sqlcipher,
        nodeId: header.deviceId,
        schema: schema,
      );
    } catch (_) {
      // [db] is closed now: the caller must lock and dispose its session
      // (`db.isClosed` tells it so). The next unlock reopens shared.db.
      next.wipeAll();
      rethrow;
    }
    current.wipeAll();
    return (db: reopened, sharedKeys: next);
  }

  /// Re-export attempts when writes keep arriving during a swap.
  static const _maxCatchUp = 3;

  /// Changes made on this connection so far (all attached files). Every
  /// write the app or the sync engine makes goes through this connection.
  static Future<int> _totalChanges(VaultDatabase db) async =>
      ((await db.raw.rawQuery('SELECT total_changes() AS n')).first['n'] as int?) ?? 0;

  /// shared.db → [path] under [key]; returns [_totalChanges] right after.
  Future<int> _exportShared(VaultDatabase db, String path, Uint8List key) async {
    await db.checkpoint();
    await db.raw.execute('ATTACH DATABASE ? AS rk KEY ?', [path, rawKeyLiteral(key)]);
    try {
      await db.raw.rawQuery('PRAGMA rk.journal_mode = DELETE'); // one self-contained file to rename
      await db.raw.rawQuery("SELECT sqlcipher_export('rk', 'shared')");
      final ver = await db.raw.rawQuery('PRAGMA shared.user_version');
      await db.raw.execute('PRAGMA rk.user_version = ${ver.first.values.first}');
    } finally {
      await db.raw.execute('DETACH DATABASE rk');
    }
    return _totalChanges(db);
  }

  /// private.db → [path] under [key] with the new recovery wrap and
  /// [metaEdits]; returns [_totalChanges] right after.
  Future<int> _exportPrivate(
    VaultDatabase db,
    String path,
    Uint8List key,
    String wrapped,
    Map<String, String?> metaEdits,
  ) async {
    await db.checkpoint();
    await db.raw.execute('ATTACH DATABASE ? AS rk KEY ?', [path, rawKeyLiteral(key)]);
    try {
      await db.raw.rawQuery('PRAGMA rk.journal_mode = DELETE'); // one self-contained file to rename
      await db.raw.rawQuery("SELECT sqlcipher_export('rk', 'main')");
      final ver = await db.raw.rawQuery('PRAGMA main.user_version');
      await db.raw.execute('PRAGMA rk.user_version = ${ver.first.values.first}');
      await db.raw.execute(
        'INSERT OR REPLACE INTO rk.vault_meta(key, value) VALUES (?, ?)',
        [CryptoMeta.recoveryWrappedMk, wrapped],
      );
      for (final e in metaEdits.entries) {
        final value = e.value;
        if (value == null) {
          await db.raw.execute('DELETE FROM rk.vault_meta WHERE key = ?', [e.key]);
        } else {
          await db.raw.execute('INSERT OR REPLACE INTO rk.vault_meta(key, value) VALUES (?, ?)', [e.key, value]);
        }
      }
    } finally {
      await db.raw.execute('DETACH DATABASE rk');
    }
    return _totalChanges(db);
  }

  String get _redoPrivateDb => '${paths.pendingPrivateDb}.redo';

  /// After the commit point, before the swap: writes that reached the live
  /// private.db after the first export are copied by exporting again into
  /// a side file that atomically replaces the pending copy. A failure keeps
  /// the earlier complete copy (only those late writes are lost) — it must
  /// never fail a rotation that is already committed.
  Future<void> _catchUpPrivateExport(
    VaultDatabase db,
    Uint8List key,
    String wrapped,
    Map<String, String?> metaEdits,
    int mark,
  ) async {
    var seen = mark;
    for (var i = 0; i < _maxCatchUp; i++) {
      try {
        if (await _totalChanges(db) == seen) return;
        await _deleteFamily(_redoPrivateDb);
        seen = await _exportPrivate(db, _redoPrivateDb, key, wrapped, metaEdits);
        for (final suffix in ['-journal', '-wal', '-shm']) {
          await _deleteIfExists(File('${paths.pendingPrivateDb}$suffix'));
        }
        await File(_redoPrivateDb).rename(paths.pendingPrivateDb);
      } catch (_) {
        try {
          await _deleteFamily(_redoPrivateDb);
        } catch (_) {}
        return;
      }
    }
  }

  static Future<void> _deleteFamily(String path) async {
    for (final suffix in ['', '-journal', '-wal', '-shm']) {
      await _deleteIfExists(File('$path$suffix'));
    }
  }

  // ============================================ owner: master-key rotation

  /// Owner: replace the Master Key and every key DERIVED from it
  /// ([VaultKeys]: private.db SQLCipher key, behaviour-profile key and the
  /// private sync-package key), wrapped under [newRecoveryPhrase].
  ///
  /// The owner's X25519 and Ed25519 key pairs are random (not MK-derived)
  /// and live in private.db `vault_meta`: an application that rotates them
  /// with the kit passes the new values in [metaEdits], so they commit
  /// atomically with the new Master Key (staff devices pinned the old
  /// public keys at pairing and must be paired again). Household keys are
  /// not MK-derived either: rotate them with a new household epoch
  /// ([rekeyOwnerShared]).
  ///
  /// Writes that reach [db] between the export and the swap are carried
  /// over by re-exporting after the commit point (bounded; see
  /// [_catchUpPrivateExport]). Writes attempted after [db] closes fail
  /// with "Vault is locked" instead of being silently dropped.
  ///
  /// Two-phase, so a cancelled Face ID or a crash never strands the data:
  ///  1. export private.db under the new key into `private.db.rekey`, with
  ///     the new recovery wrap and [metaEdits] applied; re-seal the
  ///     behaviour profile into `behavior_profile.qlb.rekey`. The live
  ///     files are untouched.
  ///  2. store the new MK behind biometrics ([KeyRelease.importMasterKey])
  ///     — the commit point.
  ///  3. close [db], swap the pending files in, reopen under the new keys.
  ///     If this is interrupted, the next [unlock] finishes the swap (the
  ///     hardware already holds the new MK).
  ///
  /// Caller contract: if this throws while `db.isClosed` is false, NOTHING
  /// changed and [db] / [current] are still valid. If `db.isClosed` is
  /// true, the new key was (or may have been) committed: lock the vault;
  /// the next unlock completes or discards the rotation, depending on
  /// which key the hardware actually holds. On success [current] is wiped and [shared] is
  /// carried over unchanged. [metaEdits] are private `vault_meta` rows to
  /// set (value) or delete (null) in the new file.
  Future<OwnerSession> rotateOwnerMasterKey({
    required VaultDatabase db,
    required VaultHeader header,
    required VaultKeys current,
    required SharedKeys shared,
    required String newRecoveryPhrase,
    EncryptedJsonStore? behaviorStore,
    Map<String, String?> metaEdits = const {},
  }) async {
    if (!db.hasPrivate) throw StateError('rotateOwnerMasterKey requires an owner connection');
    if (!RecoveryPhrase.isValid(newRecoveryPhrase)) throw const FormatException('Invalid recovery phrase');
    final mk = randomKey32();
    final next = await VaultKeys.derive(mk, header.vaultId);
    var importing = false;
    var committed = false;
    String? prevFlag;
    var flagWritten = false;
    try {
      final wrapped = await RecoveryPhrase.wrapMasterKey(mk, newRecoveryPhrase, header.vaultId);

      // 1) prepare
      await _discardPendingOwnerRotation();
      final mark = await _exportPrivate(db, paths.pendingPrivateDb, next.sqlcipher, wrapped, metaEdits);
      final behavior = await behaviorStore?.resealFor(next.behavior);
      if (behavior != null) await paths.pendingBehaviorProfile.writeAsBytes(behavior, flush: true);

      // Flag "rotation unconfirmed" before the commit point; the next unlock
      // compares it with the key that is actually active.
      prevFlag = await _readFile(paths.kitRotationFlag);
      await _writeKitRotationFlag(wrapped, 'pending');
      flagWritten = true;

      // 2) commit: the new MK goes behind biometrics.
      importing = true;
      await keyRelease.importMasterKey(mk, reason: _prompts().rotateMasterKey);
      committed = true;

      // 3) swap and reopen. Writes made while Face ID was up (sync merge,
      //    a save elsewhere) went to the old file: carry them over first.
      await _catchUpPrivateExport(db, next.sqlcipher, wrapped, metaEdits, mark);
      await db.close();
      await _promotePendingOwnerRotation();
      final reopened = await VaultDatabase.open(
        sharedPath: paths.sharedDb,
        sharedKey: shared.sqlcipher,
        privatePath: paths.privateDb,
        privateKey: next.sqlcipher,
        nodeId: header.deviceId,
        schema: schema,
      );
      current.wipeAll();
      return OwnerSession(db: reopened, header: header, privateKeys: next, sharedKeys: shared);
    } catch (e) {
      next.wipeAll();
      final confirmedCancel = e is VaultKeyException && e.failure == KeyFailure.cancelled;
      if (committed || (importing && !confirmedCancel)) {
        // Committed, or the native import failed in a way we cannot
        // classify: the hardware may hold either key. Keep the pending
        // files (the next unlock keeps whichever copy the stored key
        // actually opens) and close [db] so the caller locks the vault.
        if (!db.isClosed) await db.close(); // contract: possibly committed ⇒ closed
      } else {
        // Never committed: either the import never started, or the native
        // bridge reported a CONFIRMED cancel, which it only does after
        // leaving the old key and its files untouched (atomic slot swap).
        try {
          await _discardPendingOwnerRotation();
        } catch (_) {}
        // Nothing changed: restore the previous flag (e.g. an earlier
        // "reverted" warning must survive a cancelled retry).
        if (flagWritten) {
          final pf = prevFlag;
          try {
            if (pf == null) {
              await _deleteIfExists(paths.kitRotationFlag);
            } else {
              await paths.kitRotationFlag.writeAsString(pf, flush: true);
            }
          } catch (_) {}
        }
      }
      rethrow;
    } finally {
      wipe(mk);
    }
  }

  // ------------------------------------------ kit rotation confirmation

  /// Owner: true when the last Emergency-Kit rotation did NOT take effect —
  /// at unlock the hardware released the OLD master key (e.g. an iOS crash
  /// between the two Keychain slot writes). The new kit then opens nothing;
  /// the owner must keep the old kit and rotate again. Cleared by the
  /// first unlock that finds the new key active.
  Future<bool> kitRotationReverted() async {
    final j = await _readKitRotationFlag();
    return j != null && j['state'] == 'reverted';
  }

  Future<void> _checkKitRotationFlag(String? activeWrap) async {
    try {
      final j = await _readKitRotationFlag();
      if (j == null) return;
      final active = activeWrap == null ? null : await _wrapHash(activeWrap);
      if (active != null && active == j['wrap']) {
        await _deleteIfExists(paths.kitRotationFlag); // the new kit is the live one
      } else if (j['state'] != 'reverted') {
        await paths.kitRotationFlag.writeAsString(jsonEncode({...j, 'state': 'reverted'}), flush: true);
      }
    } catch (_) {
      // Never block an unlock on this bookkeeping.
    }
  }

  Future<void> _writeKitRotationFlag(String wrapped, String state) async {
    final hash = await _wrapHash(wrapped);
    await paths.kitRotationFlag.writeAsString(
      jsonEncode({'v': 1, 'at': DateTime.now().toUtc().millisecondsSinceEpoch, 'wrap': hash, 'state': state}),
      flush: true,
    );
  }

  Future<Map<String, dynamic>?> _readKitRotationFlag() async {
    final s = await _readFile(paths.kitRotationFlag);
    if (s == null) return null;
    try {
      final j = jsonDecode(s);
      return j is Map<String, dynamic> ? j : null;
    } catch (_) {
      return null;
    }
  }

  static Future<String?> _readFile(File f) async {
    try {
      return await f.exists() ? await f.readAsString() : null;
    } catch (_) {
      return null;
    }
  }

  /// Public fingerprint of a recovery wrap (the wrap travels in every
  /// package header, so its hash reveals nothing).
  static Future<String> _wrapHash(String wrapped) async {
    final h = await Sha256().hash(utf8.encode(wrapped));
    return h.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// At unlock: a pending rotation copy exists → keep whichever file the
  /// released key opens. Live file opens → rotation never committed,
  /// discard. Only the pending copy opens → committed, finish the swap.
  Future<void> _settlePendingOwnerRotation(VaultKeys priv) async {
    await _deleteFamily(_redoPrivateDb); // an interrupted catch-up export: never complete
    if (!await File(paths.pendingPrivateDb).exists()) {
      await _deleteIfExists(paths.pendingBehaviorProfile); // leftover of a discard
      return;
    }
    if (await _opensWith(paths.privateDb, priv.sqlcipher)) {
      await _discardPendingOwnerRotation();
    } else if (await _opensWith(paths.pendingPrivateDb, priv.sqlcipher)) {
      await _promotePendingOwnerRotation();
    }
  }

  /// Behaviour profile first, private.db last: while `private.db.rekey`
  /// exists the swap is unfinished and [_settlePendingOwnerRotation]
  /// completes it.
  Future<void> _promotePendingOwnerRotation() async {
    final pb = paths.pendingBehaviorProfile;
    if (await pb.exists()) await pb.rename(paths.behaviorProfile.path);
    final pdb = File(paths.pendingPrivateDb);
    if (!await pdb.exists()) return;
    for (final suffix in ['-wal', '-shm', '-journal']) {
      await _deleteIfExists(File('${paths.privateDb}$suffix'));
    }
    await pdb.rename(paths.privateDb);
  }

  Future<void> _discardPendingOwnerRotation() async {
    await _deleteFamily(paths.pendingPrivateDb);
    await _deleteFamily(_redoPrivateDb);
    await _deleteIfExists(paths.pendingBehaviorProfile);
  }

  /// At staff unlock: keep the pending credentials only if they — and not
  /// the live ones — open shared.db (the rekey ran, the rename did not).
  Future<void> _settlePendingStaffCredentials(StaffDeviceKeys dk) async {
    final pending = _pendingCredsStore(dk);
    if (!await pending.file.exists()) return;
    Map<String, dynamic>? next;
    try {
      next = await pending.load();
    } catch (_) {
      next = null; // torn write or a previous device key: unusable
    }
    if (next != null && !await _credsOpenShared(() => _credsStore(dk).load()) && await _credsOpenShared(() async => next!)) {
      await pending.file.rename(paths.staffCredentials.path);
    } else {
      await _deleteIfExists(pending.file);
    }
  }

  Future<bool> _credsOpenShared(Future<Map<String, dynamic>> Function() load) async {
    SharedKeys? keys;
    try {
      final creds = await load();
      final hk = base64Decode(creds[StaffCredentialFields.householdKey] as String);
      final SharedKeys k;
      try {
        k = await SharedKeys.derive(hk, creds[StaffCredentialFields.vaultId] as String, creds[StaffCredentialFields.epoch] as int);
      } finally {
        wipe(hk);
      }
      keys = k;
      return await _opensWith(paths.sharedDb, k.sqlcipher);
    } catch (_) {
      return false;
    } finally {
      keys?.wipeAll();
    }
  }

  /// A `shared.db.rekey` export is complete only when it has no hot
  /// rollback journal (export interrupted) and carries a non-zero
  /// user_version — set as the very last export step; a fresh file is 0.
  Future<bool> _pendingSharedComplete(String path, Uint8List key) async {
    if (!await File(path).exists() || await File('$path-journal').exists()) return false;
    Database? d;
    try {
      d = await VaultDatabase.openKeyed(path, key, readOnly: true);
      final v = await d.rawQuery('PRAGMA user_version');
      return ((v.first.values.first as int?) ?? 0) > 0;
    } catch (_) {
      return false;
    } finally {
      try {
        await d?.close();
      } catch (_) {}
    }
  }

  /// True if [key] actually decrypts [path] (a real read, not just open).
  Future<bool> _opensWith(String path, Uint8List key) async {
    if (!await File(path).exists()) return false;
    Database? d;
    try {
      d = await VaultDatabase.openKeyed(path, key, readOnly: true);
      await d.rawQuery('SELECT count(*) FROM sqlite_master');
      return true;
    } catch (_) {
      return false;
    } finally {
      try {
        await d?.close();
      } catch (_) {}
    }
  }

  static Future<void> _deleteIfExists(File f) async {
    if (await f.exists()) await f.delete();
  }

  // ============================================================== restore

  /// Owner restore on a new device. private.db / shared.db were already
  /// written by the caller's restore flow; [mk] was unwrapped from the
  /// recovery phrase. Protects it with this device's biometrics and opens.
  Future<OwnerSession> completeOwnerRestore({required String vaultId, required Uint8List mk}) async {
    await keyRelease.excludeFromBackup(paths.dir.path);
    await keyRelease.importMasterKey(mk, reason: _prompts().protectRestored);
    final h = VaultHeader(
      vaultId: vaultId,
      deviceId: newId(), // fresh HLC node; never reuse another device's id
      role: 'owner',
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    await paths.writeHeader(h);
    return _openOwner(h, mk);
  }

  /// Unwrap the master key from a recovery phrase (does not store it).
  Future<Uint8List> unwrapWithRecoveryPhrase({
    required String wrappedMasterKey,
    required String phrase,
    required String vaultId,
  }) =>
      RecoveryPhrase.unwrapMasterKey(wrappedMasterKey, phrase, vaultId);

  /// Revoked / signing out: destroy the hardware key and all local files.
  Future<void> wipeDevice() async {
    await keyRelease.destroy();
    await paths.wipeAll();
  }

  EncryptedJsonStore _credsStore(StaffDeviceKeys dk) =>
      EncryptedJsonStore(file: paths.staffCredentials, key: dk.credentials, aadLabel: 'staff-creds');

  /// Same key and AAD as [_credsStore], so committing is a file rename.
  EncryptedJsonStore _pendingCredsStore(StaffDeviceKeys dk) =>
      EncryptedJsonStore(file: paths.pendingStaffCredentials, key: dk.credentials, aadLabel: 'staff-creds');
}
