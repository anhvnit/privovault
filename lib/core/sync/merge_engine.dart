import 'dart:io';
import 'dart:typed_data';

import 'package:privovault_crypto/privovault_crypto.dart' show Database, Sqflite, Transaction;

import '../db/vault_database.dart';
import '../roles.dart' show StaffCapabilities;
import '../util/hlc.dart';
import 'package_format.dart' show PackageMalformed;

/// Who produced a peer snapshot — decides what we accept from it.
enum PeerAuthority {
  /// Another owner device: full authority over both scopes.
  owner,

  /// A staff device: may only create/modify rows it authored, in the
  /// staff-writable tables. Everything else in its snapshot is ignored.
  staff,
}

/// Tables a staff device may write. Owner-only shared tables (vehicles,
/// categories, staff_members, compliance, reminders) are never accepted from staff.
const kStaffWritableTables = {
  'household_chat',
  'household_expenses',
  'odometer_readings',
  'fuel_logs',
  'service_records',
  'mileage_trips',
  'household_recurring',
};

class MergeReport {
  int rowsApplied = 0;
  int conflicts = 0;

  /// Rows refused: written by someone other than the sending staff device,
  /// outside its capabilities (category / vehicle / amount limit / fuel /
  /// service), or with a malformed HLC.
  int rejectedByAuthority = 0;

  /// Rows skipped because their HLC lies more than [HlcClock.maxDriftMs]
  /// ahead of this device's clock. The caller must re-read the file on a
  /// later pass (they may become acceptable once clocks agree).
  int deferredFuture = 0;

  /// Lowest HLC among the deferred rows ('' if none): the file is worth
  /// re-reading once the wall clock reaches its time minus the max drift.
  String minDeferredHlc = '';

  /// Highest HLC among ACCEPTED rows ('' if none).
  String peerMaxHlc = '';
}

class SchemaTooNew implements Exception {
  @override
  String toString() => 'A newer app version wrote this data. Update the app to sync.';
}

/// Deterministic, idempotent row-level merge of a peer snapshot (CRDT-style
/// last-writer-wins register per row, ordered by Hybrid Logical Clock).
///
/// * Same input ⇒ same result on every device, in any order (commutative,
///   idempotent): a row is replaced only when `peer.hlc > local.hlc`.
/// * Tombstones (`deleted_at`) are ordinary updates, so deletes replicate.
/// * Rows changed on BOTH sides since the last merge with this peer are
///   genuine conflicts: the HLC winner is applied and the loser is saved to
///   `sync_conflicts` (locally encrypted) for the Secure Resolution screen.
///   Nothing about a conflict ever leaves the device in plaintext.
///
/// Staff peers (owner side) are additionally held to the owner's rules:
/// `household_expenses.status` (approval / reimbursement) is owner-only, and
/// every row is re-checked against `staff_members.capabilities_json` —
/// the checks on the staff phone are a convenience, not a boundary.
class MergeEngine {
  MergeEngine(this.db);
  final VaultDatabase db;

  /// Rows up to this far ahead of our clock are deferred (retried later);
  /// rows further ahead are rejected.
  static const maxDeferMs = 24 * 60 * 60 * 1000;

  /// Replicated owner key state (see OwnerKeyState.table).
  static const _ownerKeyStateTable = 'owner_key_state';

  /// Staff-writable tables that reference a vehicle.
  static const _vehicleTables = {
    'household_expenses',
    'odometer_readings',
    'fuel_logs',
    'service_records',
    'mileage_trips',
  };

  Future<MergeReport> merge({
    required File peerFile,
    required Uint8List peerSqlcipherKey,
    required DataScope scope,
    required String peerDeviceId,
    required PeerAuthority authority,
    required String baseHlc, // peer's max_hlc at our previous merge ('' if never)
  }) async {
    final raw = db.raw;
    final report = MergeReport();
    final staffSide = !db.hasPrivate; // this device holds only shared.db
    final localSchema = scope == DataScope.shared && db.hasPrivate ? 'shared' : 'main';

    // Owner: what this staff member may log (re-validated here).
    final caps = authority == PeerAuthority.staff ? await _staffCaps(peerDeviceId) : null;

    // A peer file is attacker-controlled input: never let its schema
    // (views, triggers, defaults, generated columns) run functions here.
    final prevTrusted = Sqflite.firstIntValue(await raw.rawQuery('PRAGMA trusted_schema'));
    await raw.execute('PRAGMA trusted_schema = OFF');
    try {
      await raw.execute('ATTACH DATABASE ? AS peer KEY ?', [peerFile.path, rawKeyLiteral(peerSqlcipherKey)]);
      try {
        await _validatePeer(raw, scope, authority, localSchema);

        final peerVersion = Sqflite.firstIntValue(await raw.rawQuery('PRAGMA peer.user_version')) ?? 0;
        final localVersion = Sqflite.firstIntValue(await raw.rawQuery('PRAGMA $localSchema.user_version')) ?? 0;
        if (peerVersion > localVersion) throw SchemaTooNew();

        final peerTables = {
          for (final r in await raw.rawQuery("SELECT name FROM peer.sqlite_master WHERE type='table'")) r['name']! as String,
        };
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        // p.hlc < ceiling  ⇔  physical time ≤ now + max drift.
        final ceiling = _sqlLiteral(HlcClock.floor(now + HlcClock.maxDriftMs + 1));
        // Rows further ahead than this are refused outright (a broken or
        // hostile clock), not deferred: they would never become valid soon.
        final deferLimit = _sqlLiteral(HlcClock.floor(now + maxDeferMs + 1));
        const wellFormed = "length(p.hlc) > 21 AND substr(p.hlc, 16, 1) = '-' AND substr(p.hlc, 21, 1) = '-'"
            " AND substr(p.hlc, 1, 15) NOT GLOB '*[^0-9]*' AND substr(p.hlc, 17, 4) NOT GLOB '*[^0-9a-f]*'";
        var maxAccepted = '';

        await raw.transaction((txn) async {
          await txn.execute('PRAGMA defer_foreign_keys = ON');
          for (final table in tablesOf(scope)) {
            if (!peerTables.contains(table)) continue;
            if (authority == PeerAuthority.staff && !kStaffWritableTables.contains(table)) continue;

            final target = db.qualified(table, scope);
            final pk = pkOf(table);
            final cols = await _commonColumns(txn, localSchema, table);
            final colList = cols.join(', ');
            final hasAuthor = cols.contains('author_device_id');

            // Authority filter (staff peers): row last written by that device,
            // authored by it, and not already owned by someone else locally
            // (for tables without an author column, the HLC node of the
            // local row is the authorship signal: an owner-written fuel log
            // can never be overwritten by a staff device). Plus the owner's
            // capability rules for that staff member.
            final authorityFilter = authority == PeerAuthority.owner
                ? '1'
                : '(substr(p.hlc, 22) = ?1'
                    '${hasAuthor ? ' AND p.author_device_id = ?1' : ''}'
                    ' AND NOT EXISTS (SELECT 1 FROM $target l WHERE l.$pk = p.$pk AND substr(l.hlc, 22) <> ?1)'
                    ' AND ${_capsFilter(table, cols, caps)})';
            final args = authority == PeerAuthority.owner ? <Object?>[] : <Object?>[peerDeviceId];
            // Staff may only post user messages: `system` / `vault` rows are
            // app messages, and a staff-authored one would spoof the app on
            // the owner's screen. Ignored silently (the staff phone's own
            // assistant replies are expected there and are not an attack
            // signal worth counting as "refused").
            final spoofedRole = authority == PeerAuthority.staff && table == 'household_chat' && cols.contains('role')
                ? "coalesce(p.role, '') IN ('system', 'vault')"
                : '0';
            final filter = '($wellFormed) AND p.hlc < $ceiling AND $authorityFilter AND NOT $spoofedRole';

            // Owner-only columns a staff row can never set or change.
            final forced = <String, String>{
              if (authority == PeerAuthority.staff && table == 'household_expenses' && cols.contains('status'))
                'status': "'logged'",
            };

            // Owner precedence (staff devices only). The owner device rejects
            // a staff edit to any row the owner (or another device) last
            // wrote — e.g. the owner approved an expense while the driver,
            // offline, revoked it a minute later. Plain LWW would leave the
            // driver's phone on its own newer version forever. So when this
            // staff device merges the owner's snapshot, the owner's version of
            // such a row wins regardless of clock order: both sides converge
            // on what the owner's books say.
            final ownerPrecedence = authority == PeerAuthority.owner && staffSide && kStaffWritableTables.contains(table);
            final me = _sqlLiteral(db.clock.nodeId);
            String override(String peer, String local) => ownerPrecedence
                ? '(substr($peer.hlc, 22) <> $me AND substr($local.hlc, 22) = $me)'
                : '0';

            // Refused rows (ignoring ones we already hold unchanged, so a
            // later permission change doesn't re-report old entries).
            const unchanged = 'EXISTS (SELECT 1 FROM {t} l WHERE l.{pk} = p.{pk} AND l.hlc = p.hlc)';
            final same = unchanged.replaceAll('{t}', target).replaceAll('{pk}', pk);
            final refused = Sqflite.firstIntValue(await txn.rawQuery(
                    'SELECT count(*) FROM peer.$table p WHERE NOT coalesce(($filter), 0) AND NOT $same AND NOT $spoofedRole',
                    args)) ??
                0;
            final futureRows = (await txn.rawQuery(
                    'SELECT count(*) AS n, min(p.hlc) AS h FROM peer.$table p '
                    'WHERE coalesce(($wellFormed) AND $authorityFilter, 0) AND p.hlc >= $ceiling '
                    'AND p.hlc < $deferLimit AND NOT $same',
                    args))
                .first;
            final future = (futureRows['n'] as int?) ?? 0;
            final minFuture = futureRows['h'] as String?;
            if (minFuture != null && (report.minDeferredHlc.isEmpty || minFuture.compareTo(report.minDeferredHlc) < 0)) {
              report.minDeferredHlc = minFuture;
            }
            report.deferredFuture += future;
            report.rejectedByAuthority += refused - future;

            // 1) Record genuine concurrent edits (both sides past the base).
            //    Not for owner_key_state: its rows are key material and
            //    bookkeeping with their own merge rules (OwnerKeyState) —
            //    nothing a person should pick between, and the same key row
            //    exported by two devices is not a conflict.
            if (baseHlc.isNotEmpty && table != _ownerKeyStateTable) {
              final loserJson =
                  'json_object(${cols.map((c) => "'$c', CASE WHEN p.hlc > l.hlc OR ${override('p', 'l')} THEN l.$c ELSE p.$c END").join(', ')})';
              await txn.execute('''
                INSERT INTO main.sync_conflicts (id, detected_at, table_name, row_id, winner, winner_hlc, loser_hlc, loser_row_json)
                SELECT lower(hex(randomblob(16))), $now, '$table', l.$pk,
                       CASE WHEN p.hlc > l.hlc OR ${override('p', 'l')} THEN 'remote' ELSE 'local' END,
                       max(p.hlc, l.hlc), min(p.hlc, l.hlc), $loserJson
                FROM $target l JOIN peer.$table p ON p.$pk = l.$pk
                WHERE p.hlc <> l.hlc AND ($filter)
                  AND ((l.hlc > ?${args.length + 1} AND p.hlc > ?${args.length + 1}) OR ${override('p', 'l')})
              ''', [...args, baseHlc]);
              report.conflicts += Sqflite.firstIntValue(await txn.rawQuery('SELECT changes()')) ?? 0;
            }

            // 2) Last-writer-wins upsert. `WHERE 1` disambiguates the upsert parser.
            final selectList = cols.map((c) => forced[c] ?? c).join(', ');
            // Revocation is monotonic: a later LWW write (e.g. a concurrent
            // permission edit on another owner device) can never clear it.
            final monotonic = table == 'staff_members' ? const {'revoked_at'} : const <String>{};
            final updates = cols
                .where((c) => c != pk && !forced.containsKey(c))
                .map((c) => monotonic.contains(c) ? '$c = coalesce($table.$c, excluded.$c)' : '$c = excluded.$c')
                .join(', ');
            await txn.execute('''
              INSERT INTO $target ($colList)
              SELECT $selectList FROM peer.$table p WHERE $filter
              ON CONFLICT($pk) DO UPDATE SET $updates
                WHERE excluded.hlc > $table.hlc OR ${override('excluded', table)}
            ''', args);
            report.rowsApplied += Sqflite.firstIntValue(await txn.rawQuery('SELECT changes()')) ?? 0;

            // ...and the other direction: a peer that revoked a member with
            // an OLDER HLC than our row still revokes it here. Not an LWW
            // write (hlc unchanged), so every device converges on "revoked".
            if (table == 'staff_members' && cols.contains('revoked_at')) {
              await txn.execute('''
                UPDATE $target SET revoked_at = (
                  SELECT p.revoked_at FROM peer.$table p WHERE p.$pk = $table.$pk AND ($filter))
                WHERE revoked_at IS NULL
                  AND EXISTS (SELECT 1 FROM peer.$table p WHERE p.$pk = $table.$pk AND p.revoked_at IS NOT NULL AND ($filter))
              ''', args);
              report.rowsApplied += Sqflite.firstIntValue(await txn.rawQuery('SELECT changes()')) ?? 0;
            }

            // Only accepted rows may advance our clock / the merge base.
            final m = (await txn.rawQuery('SELECT max(p.hlc) AS h FROM peer.$table p WHERE $filter', args))
                .first['h'] as String?;
            if (m != null && m.compareTo(maxAccepted) > 0) maxAccepted = m;
          }
        });
        report.peerMaxHlc = maxAccepted;
      } finally {
        await raw.execute('DETACH DATABASE peer');
      }
    } finally {
      if (prevTrusted == 1) await raw.execute('PRAGMA trusted_schema = ON');
    }
    if (report.peerMaxHlc.isNotEmpty) db.clock.observe(report.peerMaxHlc);
    // Only wake listeners (and the sync debounce) when something changed.
    if (report.rowsApplied > 0 || report.conflicts > 0) db.notifyAll();
    return report;
  }

  /// T5: the attached file must be an intact SQLite database with the
  /// layout we expect, and nothing executable in its schema.
  Future<void> _validatePeer(Database raw, DataScope scope, PeerAuthority authority, String localSchema) async {
    final qc = await raw.rawQuery('PRAGMA peer.quick_check(1)');
    if (qc.length != 1 || qc.first.values.first != 'ok') throw PackageMalformed('peer database failed integrity check');

    final objects = await raw.rawQuery('SELECT type, name FROM peer.sqlite_master');
    final tables = <String>{};
    for (final o in objects) {
      final type = o['type'] as String?;
      if (type == 'trigger' || type == 'view') throw PackageMalformed('unexpected $type in peer database');
      if (type == 'table') tables.add(o['name']! as String);
    }
    final expected = tablesOf(scope);
    if (expected.isEmpty || !tables.contains(expected.first) || !tables.contains('vault_meta')) {
      throw PackageMalformed('peer database lacks expected tables');
    }
    for (final table in expected) {
      if (!tables.contains(table)) continue; // older peer: table added later
      final peerCols = {for (final r in await raw.rawQuery('PRAGMA peer.table_info($table)')) r['name']! as String};
      if (!peerCols.contains(pkOf(table)) || !peerCols.contains('hlc')) {
        throw PackageMalformed('peer table $table lacks key columns');
      }
      if (authority == PeerAuthority.staff && kStaffWritableTables.contains(table) && !peerCols.contains('author_device_id')) {
        // Dropping the author column must not weaken the authority filter.
        final local = await raw.rawQuery('PRAGMA $localSchema.table_info($table)');
        if (local.any((r) => r['name'] == 'author_device_id')) {
          throw PackageMalformed('peer table $table lacks author column');
        }
      }
    }
  }

  /// Capabilities of a staff peer as the OWNER recorded them. Staff devices
  /// (legacy household model) don't enforce: returns `(enforce: false)`.
  /// An unknown, revoked or unreadable staff record refuses everything.
  Future<({bool enforce, StaffCapabilities? caps})> _staffCaps(String staffId) async {
    if (!db.hasPrivate) return (enforce: false, caps: null);
    final r = await db.selectOne(
      'SELECT capabilities_json, revoked_at, deleted_at FROM ${db.qualified('staff_members', DataScope.shared)} WHERE id = ?',
      [staffId],
    );
    if (r == null || r['revoked_at'] != null || r['deleted_at'] != null) return (enforce: true, caps: null);
    try {
      return (enforce: true, caps: StaffCapabilities.decode(r['capabilities_json']! as String));
    } catch (_) {
      return (enforce: true, caps: null);
    }
  }

  /// SQL condition (over peer alias `p`) a staff row must satisfy.
  /// Mirrors `DraftCommitter._checkCapabilities` on the staff phone.
  static String _capsFilter(String table, List<String> cols, ({bool enforce, StaffCapabilities? caps})? c) {
    if (c == null || !c.enforce) return '1';
    final caps = c.caps;
    if (caps == null) return '0';
    String inList(List<String> ids) => '(${ids.map(_sqlLiteral).join(', ')})';
    final parts = <String>[];
    if (table == 'fuel_logs' && !caps.canLogFuel) return '0';
    if (table == 'service_records' && !caps.canLogService) return '0';
    if (caps.vehicleIds.isNotEmpty && _vehicleTables.contains(table) && cols.contains('vehicle_id')) {
      parts.add(table == 'household_expenses'
          ? '(p.vehicle_id IS NULL OR p.vehicle_id IN ${inList(caps.vehicleIds)})'
          : 'p.vehicle_id IN ${inList(caps.vehicleIds)}');
    }
    if (table == 'household_expenses') {
      if (caps.categoryIds.isNotEmpty && cols.contains('category_id')) {
        parts.add('(p.category_id IS NULL OR p.category_id IN ${inList(caps.categoryIds)})');
      }
      final max = caps.maxAmountMinor;
      if (max != null) {
        if (!cols.contains('amount_minor')) return '0';
        // A hard ceiling: a note no longer lifts it (any text, e.g. "x",
        // did), and a row in another currency than the limit's is refused —
        // minor units of different currencies are not comparable and no
        // rate is available here. Without a limit currency the cap applies
        // to the raw minor amount.
        final cur = caps.currency;
        if (cur != null) {
          if (!cols.contains('currency')) return '0';
          parts.add('p.currency = ${_sqlLiteral(cur)}');
        }
        parts.add('p.amount_minor <= $max');
      }
    }
    return parts.isEmpty ? '1' : parts.join(' AND ');
  }

  static String _sqlLiteral(String s) => "'${s.replaceAll("'", "''")}'";

  /// Columns present in both local and peer table (tolerates older peers).
  static Future<List<String>> _commonColumns(Transaction txn, String localSchema, String table) async {
    final local = [for (final r in await txn.rawQuery('PRAGMA $localSchema.table_info($table)')) r['name']! as String];
    final peer = {for (final r in await txn.rawQuery('PRAGMA peer.table_info($table)')) r['name']! as String};
    return local.where(peer.contains).toList();
  }

  // ------------------------------------------------------- resolution

  /// Unresolved conflicts for the Secure Resolution screen.
  Future<List<Map<String, Object?>>> pendingConflicts() =>
      db.select('SELECT * FROM main.sync_conflicts WHERE resolved_at IS NULL ORDER BY detected_at DESC');

  /// User chose the version that lost: re-apply it with a fresh HLC so it
  /// wins everywhere on the next sync.
  Future<void> restoreLoser(Map<String, Object?> conflict, Map<String, Object?> loserRow) =>
      db.transaction((tx) async {
        final row = Map<String, Object?>.of(loserRow)..remove('hlc');
        await tx.upsert(conflict['table_name']! as String, row);
        await tx.execute('UPDATE main.sync_conflicts SET resolved_at = ? WHERE id = ?',
            [DateTime.now().toUtc().millisecondsSinceEpoch, conflict['id']], {'sync_conflicts'});
      });

  Future<void> acceptWinner(String conflictId) => db.execute(
      'UPDATE main.sync_conflicts SET resolved_at = ? WHERE id = ?',
      [DateTime.now().toUtc().millisecondsSinceEpoch, conflictId],
      {'sync_conflicts'});
}

/// Node id embedded in an HLC string (the device that last wrote the row).
String hlcNode(String hlc) => HlcClock.decode(hlc)?.node ?? '';
