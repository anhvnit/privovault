/// Which encrypted file a table lives in.
///
///  shared  — readable by every paired device (owner + staff); keyed by the
///            rotatable household key.
///  private — owner devices only; keyed from the owner master key.
enum DataScope { shared, private }

/// Loads one migration script (e.g. `() => rootBundle.loadString(path)`).
typedef SqlSource = Future<String> Function();

/// The application's database layout, injected into [VaultDatabase].
///
/// The package knows nothing about the app's tables: it only needs the
/// ordered migrations per file, which tables are replicated (for HLC
/// bookkeeping) and each table's primary-key column.
class VaultSchema {
  VaultSchema({
    required this.sharedMigrations,
    required this.privateMigrations,
    required this.sharedTables,
    required this.privateTables,
    this.primaryKeys = const {},
    this.extraTables = const {},
    this.maintenance = const [],
  });

  /// Index i upgrades the file from `user_version` i to i+1.
  final List<SqlSource> sharedMigrations;
  final List<SqlSource> privateMigrations;

  /// Replicated tables per scope, parents first. Every one must have
  /// `hlc TEXT NOT NULL` and `deleted_at INTEGER` columns.
  final List<String> sharedTables;
  final List<String> privateTables;

  /// Primary-key column per table when it is not `id`.
  final Map<String, String> primaryKeys;

  /// Non-replicated tables watchers may still want notified (e.g. caches).
  final Set<String> extraTables;

  /// Best-effort housekeeping statements run once after each unlock, off
  /// the critical path (e.g. purging old resolved conflicts). `?1` is bound
  /// to the current UTC time in ms. Must only touch non-replicated rows:
  /// they run without HLC stamping or change notifications.
  final List<String> maintenance;

  int get sharedVersion => sharedMigrations.length;
  int get privateVersion => privateMigrations.length;

  List<String> tablesOf(DataScope s) => s == DataScope.shared ? sharedTables : privateTables;

  String pkOf(String table) => primaryKeys[table] ?? 'id';

  Set<String> get allTables => {...sharedTables, ...privateTables, ...extraTables, 'vault_meta'};
}
