import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import '../crypto/aead.dart';
import '../db/vault_database.dart';

/// Consistent point-in-time copies of one scope, made with SQLCipher's
/// `sqlcipher_export()` into a fresh file keyed with the same SQLCipher key.
/// The resulting bytes are ciphertext; they never exist decrypted on disk.
class SnapshotService {
  SnapshotService(this.scratchDir);
  final Directory scratchDir;

  Future<File> _tmp(String tag) async {
    await scratchDir.create(recursive: true);
    return File(p.join(scratchDir.path, '$tag-${randomBytes(6).map((b) => b.toRadixString(16)).join()}.db'));
  }

  /// Export [scope] of the open [db] keyed with [sqlcipherKey] (the same key
  /// that scope is opened with) and return the file bytes.
  Future<Uint8List> export(VaultDatabase db, DataScope scope, Uint8List sqlcipherKey) async {
    final out = await _tmp('snap');
    final source = scope == DataScope.shared && db.hasPrivate ? 'shared' : 'main';
    try {
      await db.checkpoint();
      await db.raw.execute('ATTACH DATABASE ? AS snap KEY ?', [out.path, rawKeyLiteral(sqlcipherKey)]);
      try {
        await db.raw.rawQuery("SELECT sqlcipher_export('snap', '$source')");
        final v = await db.raw.rawQuery('PRAGMA $source.user_version');
        await db.raw.execute('PRAGMA snap.user_version = ${v.first.values.first}');
        // Device-local caches stay out of uploads: the price cache is
        // refetched, and sync_conflicts holds this device's losing row
        // versions for its own resolution screen. Rows only — the tables
        // stay, so the schema (and restore, which opens this file as-is)
        // is unchanged. Neither table is merged (not in tablesOf), and no
        // foreign key references them.
        await db.raw.rawQuery('PRAGMA snap.secure_delete = ON'); // no readable traces in free pages
        for (final t in const ['price_cache', 'sync_conflicts']) {
          final has = await db.raw.rawQuery("SELECT 1 FROM snap.sqlite_master WHERE type = 'table' AND name = ?", [t]);
          if (has.isNotEmpty) await db.raw.execute('DELETE FROM snap.$t');
        }
      } finally {
        await db.raw.execute('DETACH DATABASE snap');
      }
      return await out.readAsBytes();
    } finally {
      await _shred(out);
    }
  }

  /// Write downloaded snapshot bytes to a scratch file for ATTACH.
  Future<File> stage(Uint8List bytes, String tag) async {
    final f = await _tmp(tag);
    await f.writeAsBytes(bytes, flush: true);
    return f;
  }

  Future<void> discard(File f) => _shred(f);

  static Future<void> _shred(File f) async {
    for (final x in [f, File('${f.path}-wal'), File('${f.path}-shm'), File('${f.path}-journal')]) {
      if (await x.exists()) await x.delete();
    }
  }
}
