/// PrivoVault crypto core: biometric key release and SQLCipher vault
/// initialisation. No UI, no localisation, no application tables.
///
/// ```dart
/// final handshake = VaultHandshake(
///   paths: await VaultPaths.resolve(),
///   keyRelease: const HardwareBoundKeyRelease(),
///   schema: mySchema,
///   prompts: () => myLocalizedPrompts,
/// );
/// final session = await handshake.unlock(); // OwnerSession | StaffSession
/// ```
library privovault_crypto;

// Biometrics → key release
export 'src/biometric/key_release.dart'
    show KeyRelease, HardwareBoundKeyRelease, LocalAuthKeyRelease, BiometricGate, Biometry, KeyFailure, VaultKeyException, randomKey32;

// Primitives
export 'src/primitives/aead.dart' show Aead, randomBytes, wipe, constantTimeEquals, sha256;
export 'src/primitives/keys.dart' show VaultKeys, SharedKeys, StaffDeviceKeys, hkdf;
export 'src/primitives/recovery.dart' show RecoveryPhrase;
export 'src/primitives/encrypted_kit.dart' show EncryptedRecoveryKit;
export 'src/primitives/encrypted_json_store.dart' show EncryptedJsonStore;

// SQLCipher
export 'src/db/vault_schema.dart' show VaultSchema, DataScope, SqlSource;
export 'src/db/vault_database.dart'
    show VaultDatabase, VaultExecutor, VaultWrongKey, VaultCipherUnavailable, rawKeyLiteral, splitSqlScript;
export 'src/db/hlc.dart' show HlcClock;
export 'src/db/ids.dart' show newId;

// Handshake
export 'src/vault/vault_paths.dart' show VaultPaths, VaultHeader;
export 'src/vault/crypto_meta.dart' show CryptoMeta, SharedCryptoMeta, UnlockPrompts;
export 'src/vault/vault_handshake.dart' show VaultHandshake, OwnerSession, StaffSession, StaffCredentialFields, VaultSeed;

// sqflite types needed by callers doing raw SQL (sync/merge); the package
// is the single owner of the SQLCipher dependency.
export 'package:sqflite_sqlcipher/sqflite.dart' show Database, DatabaseExecutor, Transaction, Batch, Sqflite, DatabaseException;
