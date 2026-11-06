import 'dart:async';

import 'package:sqflite_sqlcipher/sqflite.dart';

import '../primitives/aead.dart' show isWipedKey;
import 'hlc.dart';
import 'ids.dart';
import 'vault_schema.dart';

class VaultCipherUnavailable implements Exception {
  @override
  String toString() => 'SQLCipher is not active. Refusing to use a plaintext database.';
}

class VaultWrongKey implements Exception {
  @override
  String toString() => 'Vault key rejected (file is corrupt or the key is wrong).';
}

/// SQLCipher raw-key literal. SQLCipher recognises the `x'<64 hex>'` form in
/// the key material itself and uses it directly as the 256-bit key, skipping
/// the 256k-iteration PBKDF2 a passphrase would trigger (fast unlock).
String rawKeyLiteral(List<int> key) {
  if (key.length != 32) throw ArgumentError('SQLCipher key must be 32 bytes');
  // Never key (or export) a database with a zeroed key from a locked vault.
  if (isWipedKey(key)) throw StateError('Key material was wiped (vault locked)');
  const d = '0123456789abcdef';
  final sb = StringBuffer("x'");
  for (final x in key) {
    sb
      ..write(d[x >> 4])
      ..write(d[x & 15]);
  }
  return (sb..write("'")).toString();
}

// ======================================================================
// Executor: the query surface shared by the database and a transaction.
// ======================================================================

/// Everything feature code may do against the vault. Implemented by
/// [VaultDatabase] (auto-commit) and by the `tx` handed to
/// [VaultDatabase.transaction]. Inside a transaction ALWAYS use `tx`:
/// sqflite serialises on one native connection, so calling the outer
/// database from inside a transaction deadlocks.
abstract class VaultExecutor {
  Future<List<Map<String, Object?>>> select(String sql, [List<Object?> params = const []]);
  Future<Map<String, Object?>?> selectOne(String sql, [List<Object?> params = const []]);
  Future<void> execute(String sql, [List<Object?> params = const [], Set<String> touches = const {}]);
  Future<String> upsert(String table, Map<String, Object?> row);
  Future<void> patch(String table, String id, Map<String, Object?> fields);
  Future<void> softDelete(String table, String id);
}

class _Exec implements VaultExecutor {
  _Exec(this._x, this._clock, this._schema, this._onChange);

  final DatabaseExecutor _x;
  final HlcClock _clock;
  final VaultSchema _schema;
  final void Function(Set<String>) _onChange;

  @override
  Future<List<Map<String, Object?>>> select(String sql, [List<Object?> params = const []]) =>
      _x.rawQuery(sql, params);

  @override
  Future<Map<String, Object?>?> selectOne(String sql, [List<Object?> params = const []]) async {
    final rows = await _x.rawQuery(sql, params);
    return rows.isEmpty ? null : rows.first;
  }

  @override
  Future<void> execute(String sql, [List<Object?> params = const [], Set<String> touches = const {}]) async {
    await _x.execute(sql, params);
    _onChange(touches);
  }

  /// INSERT … ON CONFLICT DO UPDATE (never REPLACE, so FK children survive),
  /// stamping `hlc` and generating the primary key when absent.
  @override
  Future<String> upsert(String table, Map<String, Object?> row) async {
    final pk = _schema.pkOf(table);
    final data = <String, Object?>{...row};
    data[pk] ??= newId();
    data['hlc'] = _clock.now();
    final cols = data.keys.toList(growable: false);
    final updates = cols.where((c) => c != pk).map((c) => '$c = excluded.$c').join(', ');
    await _x.execute(
      'INSERT INTO $table (${cols.join(',')}) VALUES (${List.filled(cols.length, '?').join(',')}) '
      'ON CONFLICT($pk) DO UPDATE SET $updates',
      [for (final c in cols) data[c]],
    );
    _onChange({table});
    return data[pk]! as String;
  }

  @override
  Future<void> patch(String table, String id, Map<String, Object?> fields) async {
    final data = {...fields, 'hlc': _clock.now()};
    await _x.execute(
      'UPDATE $table SET ${data.keys.map((c) => '$c = ?').join(', ')} WHERE ${_schema.pkOf(table)} = ?',
      [...data.values, id],
    );
    _onChange({table});
  }

  /// Tombstone. Synced rows are never hard-deleted (deletes must replicate).
  @override
  Future<void> softDelete(String table, String id) =>
      patch(table, id, {'deleted_at': DateTime.now().toUtc().millisecondsSinceEpoch});
}

// ======================================================================
// Database
// ======================================================================

/// Open SQLCipher vault connection.
///
/// * Owner: private.db is `main`, shared.db is ATTACHed as `shared`.
///   Unqualified table names resolve to whichever file holds the table, so
///   feature code never needs to know about the split.
/// * Staff: shared.db is `main`; private tables do not exist in the
///   connection at all (queries fail with "no such table").
///
/// Performance notes (sqflite crosses a platform channel per call):
///  * group writes in [transaction] — one native round trip per statement
///    but a single fsync at commit;
///  * prefer one aggregate query per widget over N small ones;
///  * WAL + synchronous=NORMAL on both files, an 8 MB page cache per file
///    (hot pages are not re-decrypted), in-memory temp b-trees, and
///    `PRAGMA optimize` on close; rows are plain maps (no reflection).
class VaultDatabase implements VaultExecutor {
  VaultDatabase._(this._db, this.clock, this.path, this.schema, {required this.hasPrivate}) {
    _exec = _Exec(_db, clock, schema, _markChanged);
  }

  final Database _db;
  final HlcClock clock;
  final String path;

  /// The application layout this connection was opened with.
  final VaultSchema schema;

  /// True only on owner devices (private file open as `main`).
  final bool hasPrivate;
  late final _Exec _exec;

  final _changes = StreamController<Set<String>>.broadcast();
  final Set<String> _pending = {};
  bool _inTx = false;
  bool _closed = false;

  // --------------------------------------------------------------- open

  static Future<VaultDatabase> open({
    required String sharedPath,
    required List<int> sharedKey,
    String? privatePath,
    List<int>? privateKey,
    required String nodeId,
    required VaultSchema schema,
  }) async {
    final owner = privatePath != null;
    if (owner && privateKey == null) throw ArgumentError('privateKey required with privatePath');

    // Fast path (every unlock but the first after an update): one
    // connection, user_version read from it. Only when a file is behind is
    // it closed and each file migrated on its own connection — migration
    // scripts use unqualified names and must never run while another file
    // is attached.
    var db = await _openMain(sharedPath, sharedKey, privatePath, privateKey);
    try {
      final sharedBehind = await _userVersion(db, owner ? 'shared' : 'main') < schema.sharedVersion;
      final privateBehind = owner && await _userVersion(db, 'main') < schema.privateVersion;
      if (sharedBehind || privateBehind) {
        await db.close();
        if (sharedBehind) await _migrate(sharedPath, sharedKey, schema.sharedMigrations);
        if (privateBehind) await _migrate(privatePath!, privateKey!, schema.privateMigrations);
        db = await _openMain(sharedPath, sharedKey, privatePath, privateKey);
      }
    } catch (_) {
      if (db.isOpen) await db.close();
      rethrow;
    }
    try {
      final vdb = VaultDatabase._(db, HlcClock(nodeId), privatePath ?? sharedPath, schema, hasPrivate: owner);
      // The clock starts at 0: seed it with the newest stored HLC of each
      // scope so local edits never get a lower timestamp than merged rows.
      // Cheap: every replicated table has an `hlc` index (schema v5/v4), so
      // each max() is one b-tree seek instead of a full decrypting scan.
      for (final scope in owner ? DataScope.values : const [DataScope.shared]) {
        if (schema.tablesOf(scope).isEmpty) continue;
        final h = await vdb.maxHlc(scope);
        if (h.isNotEmpty) vdb.clock.seed(h);
      }
      unawaited(vdb._runMaintenance());
      return vdb;
    } catch (_) {
      await db.close();
      rethrow;
    }
  }

  /// The connection a [VaultDatabase] wraps: private.db as `main` with
  /// shared.db attached (owner), or shared.db alone (staff).
  static Future<Database> _openMain(String sharedPath, List<int> sharedKey, String? privatePath, List<int>? privateKey) async {
    if (privatePath == null) return openKeyed(sharedPath, sharedKey);
    final db = await openKeyed(privatePath, privateKey!);
    try {
      await db.execute('ATTACH DATABASE ? AS shared KEY ?', [sharedPath, rawKeyLiteral(sharedKey)]);
      try {
        await db.rawQuery('SELECT count(*) FROM shared.sqlite_master');
      } on DatabaseException {
        throw VaultWrongKey();
      }
      // Per-schema PRAGMAs set in onConfigure only reach `main`: without
      // these the attached file would fsync at FULL and use the 2 MB default cache.
      await db.rawQuery('PRAGMA shared.journal_mode = WAL'); // persistent; normally already set
      await db.rawQuery('PRAGMA shared.synchronous = NORMAL');
      await db.rawQuery('PRAGMA shared.cache_size = -8000');
      return db;
    } catch (_) {
      await db.close();
      rethrow;
    }
  }

  static Future<int> _userVersion(Database db, String schemaName) async =>
      Sqflite.firstIntValue(await db.rawQuery('PRAGMA $schemaName.user_version')) ?? 0;

  /// Opens one keyed file with nothing attached (sync engine, migrations).
  /// `singleInstance: false` so the sync engine can open snapshots freely.
  static Future<Database> openKeyed(String path, List<int> key, {bool readOnly = false}) async {
    final Database db;
    try {
      db = await openDatabase(
        path,
        password: rawKeyLiteral(key),
        readOnly: readOnly,
        singleInstance: false,
        onConfigure: (d) async {
          // ON by owner decision: SQLCipher wipes freed memory and locks
          // key material pages — decrypted balances must not linger in RAM.
          await d.rawQuery('PRAGMA cipher_memory_security = ON');
          await d.execute('PRAGMA foreign_keys = ON');
          await d.rawQuery('PRAGMA secure_delete = ON'); // returns a row → rawQuery
          await d.rawQuery('PRAGMA cache_size = -8000'); // 8 MB of decrypted pages
          await d.rawQuery('PRAGMA temp_store = MEMORY'); // UNION / ORDER BY temporaries
          if (!readOnly) {
            await d.rawQuery('PRAGMA journal_mode = WAL');
            await d.execute('PRAGMA synchronous = NORMAL');
          }
        },
      );
    } on DatabaseException catch (e) {
      if (e.toString().contains('file is not a database') || e.toString().contains('encrypted')) {
        throw VaultWrongKey();
      }
      rethrow;
    }
    // Fail closed: if the binary somehow linked plain SQLite, cipher_version is empty.
    final v = await db.rawQuery('PRAGMA cipher_version');
    if (v.isEmpty || (v.first.values.first as String?)?.isNotEmpty != true) {
      await db.close();
      throw VaultCipherUnavailable();
    }
    return db;
  }

  static Future<void> _migrate(String path, List<int> key, List<SqlSource> steps) async {
    final db = await openKeyed(path, key);
    try {
      final current = Sqflite.firstIntValue(await db.rawQuery('PRAGMA user_version')) ?? 0;
      if (current >= steps.length) return;
      await db.transaction((txn) async {
        final batch = txn.batch();
        for (var v = current; v < steps.length; v++) {
          for (final stmt in splitSqlScript(await steps[v]())) {
            batch.execute(stmt);
          }
        }
        await batch.commit(noResult: true);
        await txn.execute('PRAGMA user_version = ${steps.length}');
      });
    } finally {
      await db.close();
    }
  }

  // ----------------------------------------------------- VaultExecutor

  @override
  Future<List<Map<String, Object?>>> select(String sql, [List<Object?> params = const []]) {
    _assertOpen();
    return _exec.select(sql, params);
  }

  @override
  Future<Map<String, Object?>?> selectOne(String sql, [List<Object?> params = const []]) {
    _assertOpen();
    return _exec.selectOne(sql, params);
  }

  @override
  Future<void> execute(String sql, [List<Object?> params = const [], Set<String> touches = const {}]) {
    _assertOpen();
    return _exec.execute(sql, params, touches);
  }

  @override
  Future<String> upsert(String table, Map<String, Object?> row) {
    _assertOpen();
    return _exec.upsert(table, row);
  }

  @override
  Future<void> patch(String table, String id, Map<String, Object?> fields) {
    _assertOpen();
    return _exec.patch(table, id, fields);
  }

  @override
  Future<void> softDelete(String table, String id) {
    _assertOpen();
    return _exec.softDelete(table, id);
  }

  /// Atomic unit of work. Change notifications are held until commit and
  /// dropped on rollback. Nested calls are not supported by sqflite: pass
  /// the `tx` down instead.
  Future<T> transaction<T>(Future<T> Function(VaultExecutor tx) body) async {
    _assertOpen();
    if (_inTx) throw StateError('Nested transaction: pass the outer tx instead');
    _inTx = true;
    try {
      final r = await _db.transaction((txn) => body(_Exec(txn, clock, schema, _markChanged)));
      _inTx = false;
      _flush();
      return r;
    } catch (_) {
      _inTx = false;
      _pending.clear();
      rethrow;
    }
  }

  // ------------------------------------------------------------ meta k/v
  // `vault_meta` exists in both files. Unqualified = `main` (private on
  // owner, shared on staff). Household-visible values use [sharedMeta].

  String get _sharedPrefix => hasPrivate ? 'shared.' : '';

  Future<String?> meta(String key, {VaultExecutor? tx}) async =>
      (await (tx ?? this).selectOne('SELECT value FROM main.vault_meta WHERE key = ?', [key]))?['value'] as String?;

  Future<void> setMeta(String key, String value, {VaultExecutor? tx}) => (tx ?? this)
      .execute('INSERT OR REPLACE INTO main.vault_meta(key, value) VALUES (?, ?)', [key, value], {'vault_meta'});

  Future<String?> sharedMeta(String key, {VaultExecutor? tx}) async => (await (tx ?? this)
          .selectOne('SELECT value FROM ${_sharedPrefix}vault_meta WHERE key = ?', [key]))?['value'] as String?;

  Future<void> setSharedMeta(String key, String value, {VaultExecutor? tx}) => (tx ?? this).execute(
      'INSERT OR REPLACE INTO ${_sharedPrefix}vault_meta(key, value) VALUES (?, ?)', [key, value], {'vault_meta'});

  /// Highest HLC across one scope — detects unsynced local changes.
  ///
  /// Always read from the tables (never cached): merges and the sync engine
  /// write through [raw], so an in-memory value could silently fall behind.
  /// With the per-table `hlc` indexes SQLite answers each `max(hlc)` with a
  /// single index seek, so the whole union is one cheap round trip.
  Future<String> maxHlc(DataScope scope) async {
    final prefix = scope == DataScope.shared ? _sharedPrefix : 'main.';
    final union = schema.tablesOf(scope).map((t) => 'SELECT max(hlc) AS h FROM $prefix$t').join(' UNION ALL ');
    return ((await selectOne('SELECT max(h) AS h FROM ($union)'))?['h'] as String?) ?? '';
  }

  /// Schema-qualified table name for raw sync SQL.
  String qualified(String table, DataScope scope) =>
      scope == DataScope.shared ? '$_sharedPrefix$table' : 'main.$table';

  // ------------------------------------------------------------ reactive

  /// Bookkeeping tables (sync cursors, price cache, conflict log): written
  /// by the sync engine and the market refresh themselves.
  Set<String> get _internalTables => {...schema.extraTables, 'vault_meta'};

  /// Changes to user data. Batches that only touch [_internalTables] are
  /// filtered out, so the sync trigger and broad "any write" listeners are
  /// not re-armed by sync's own bookkeeping. Use [watch] with explicit
  /// table names to observe internal tables.
  Stream<Set<String>> get changes => _changes.stream.where((s) => s.any((t) => !_internalTables.contains(t)));

  /// Delay that coalesces a burst of writes (a merge, a multi-row commit,
  /// several providers saving) into a single re-query.
  static const watchDebounce = Duration(milliseconds: 120);

  /// Emits [query] now and again whenever one of [tables] changes.
  ///
  /// * Subscribes to changes BEFORE the first query, so a write that lands
  ///   while the first query runs still triggers a refresh.
  /// * Bursts are coalesced: re-queries wait [watchDebounce] after the last
  ///   relevant change, and never overlap — a change arriving mid-query
  ///   marks the result dirty and exactly one more query follows.
  /// * A failing query emits an error but keeps the watch alive.
  Stream<T> watch<T>(Set<String> tables, Future<T> Function() query) {
    late final StreamController<T> out;
    StreamSubscription<Set<String>>? sub;
    Timer? timer;
    var running = false;
    var dirty = false;
    var cancelled = false;

    Future<void> run() async {
      if (cancelled || out.isClosed) return;
      if (running) {
        dirty = true;
        return;
      }
      running = true;
      try {
        do {
          dirty = false;
          try {
            final v = await query();
            if (!cancelled && !out.isClosed) out.add(v);
          } catch (e, st) {
            if (!cancelled && !out.isClosed) out.addError(e, st);
          }
        } while (dirty && !cancelled && !_closed);
      } finally {
        running = false;
      }
    }

    out = StreamController<T>(
      onListen: () {
        sub = _changes.stream.listen(
          (changed) {
            if (!changed.any(tables.contains)) return;
            if (running) {
              dirty = true;
              return;
            }
            timer?.cancel();
            timer = Timer(watchDebounce, run);
          },
          onDone: () {
            // Vault closed: end the stream (providers rebuild on unlock).
            timer?.cancel();
            if (!out.isClosed) out.close();
          },
        );
        unawaited(run());
      },
      onCancel: () async {
        cancelled = true;
        timer?.cancel();
        await sub?.cancel();
      },
    );
    return out.stream;
  }

  void _markChanged(Set<String> tables) {
    if (tables.isEmpty) return;
    _pending.addAll(tables);
    if (!_inTx) _flush();
  }

  void _flush() {
    if (_pending.isEmpty || _changes.isClosed) return;
    final s = Set<String>.of(_pending);
    _pending.clear();
    _changes.add(s);
  }

  void notifyAll() {
    if (!_changes.isClosed) _changes.add(schema.allTables);
  }

  /// Escape hatch for the sync engine (ATTACH, sqlcipher_export, rekey).
  Database get raw {
    _assertOpen();
    return _db;
  }

  Future<void> checkpoint() async {
    await _db.rawQuery('PRAGMA main.wal_checkpoint(TRUNCATE)');
    if (hasPrivate) await _db.rawQuery('PRAGMA shared.wal_checkpoint(TRUNCATE)');
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _changes.close();
    // Refresh planner statistics for the OR/UNION queries (bounded work:
    // analysis_limit caps rows scanned per index). Best-effort.
    try {
      await _db.rawQuery('PRAGMA analysis_limit = 400');
      await _db.rawQuery('PRAGMA optimize');
    } catch (_) {}
    await _db.close();
  }

  /// Runs [VaultSchema.maintenance] once per unlock, best-effort, directly on
  /// the connection (no HLC stamp, no change notification: these statements
  /// only touch non-replicated bookkeeping rows).
  Future<void> _runMaintenance() async {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch;
    for (final sql in schema.maintenance) {
      if (_closed) return;
      try {
        await _db.execute(sql, [now]);
      } catch (_) {
        // e.g. a table missing on a staff device — housekeeping never blocks unlock.
      }
    }
  }

  bool get isClosed => _closed;

  void _assertOpen() {
    if (_closed) throw StateError('Vault is locked');
  }
}

/// Splits a migration script into single statements (Android's execSQL runs
/// only one statement per call). Strips `--` comments; our schema contains no
/// semicolons inside string literals or triggers.
List<String> splitSqlScript(String script) {
  final noComments = script
      .split('\n')
      .map((l) {
        final i = l.indexOf('--');
        return i >= 0 ? l.substring(0, i) : l;
      })
      .join('\n');
  return noComments.split(';').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
}
