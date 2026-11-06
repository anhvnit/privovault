# privovault_crypto

PrivoVault's crypto core as a standalone Flutter package. It covers two things:

1. **Biometric key release.** A 256-bit master key is released only after Face ID, Touch ID or BiometricPrompt succeeds.
2. **SQLCipher vault initialisation.** The keys are derived and the encrypted databases are opened, attached and migrated.

It has **no UI, no localisation and no application tables**. The app supplies its schema, prompt strings and seed data.

## Contents

| Area | API |
|---|---|
| Biometrics | `KeyRelease`, `HardwareBoundKeyRelease` (default), `LocalAuthKeyRelease`, `BiometricGate`, `VaultKeyException` / `KeyFailure` |
| SQLCipher | `VaultDatabase` (owner: private `main` + `shared` attached; staff: shared only), `VaultExecutor`, `VaultSchema`, `DataScope` |
| Handshake | `VaultHandshake` → `OwnerSession` / `StaffSession`; rotation (`rekeyOwnerShared`, `applyStaffKeyRotation`), restore |
| Keys | `VaultKeys`, `SharedKeys`, `StaffDeviceKeys` (HKDF-SHA256), `Aead` (AES-256-GCM), `RecoveryPhrase` (BIP-39, 12 words), `EncryptedRecoveryKit` (Argon2id + AES-GCM, for kits saved as files) |
| Support | `VaultPaths` / `VaultHeader`, `EncryptedJsonStore`, `HlcClock`, `CryptoMeta` / `SharedCryptoMeta` |

## Usage

```dart
final schema = VaultSchema(
  sharedMigrations: [() => rootBundle.loadString('assets/sql/shared_v1.sql')],
  privateMigrations: [() => rootBundle.loadString('assets/sql/private_v1.sql')],
  sharedTables: ['categories', 'household_expenses'],
  privateTables: ['accounts', 'transactions'],
);

final handshake = VaultHandshake(
  paths: await VaultPaths.resolve(),
  keyRelease: const HardwareBoundKeyRelease(),
  schema: schema,
  prompts: () => myLocalizedPrompts, // UnlockPrompts; English default
);

// First run (owner)
final created = await handshake.createOwnerVault(
  seed: (db, tx) => db.setMeta('base_currency', 'USD', tx: tx),
);
showOnce(created.recoveryPhrase); // never persist it

// Every launch
switch (await handshake.unlock()) {
  case OwnerSession s: useOwner(s.db, s.privateKeys, s.sharedKeys);
  case StaffSession s: useStaff(s.db, s.credentials);
}
```

## Security model

- **Default key release (`HardwareBoundKeyRelease`).** On iOS the master key is a Keychain item with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and `SecAccessControl(.biometryCurrentSet)`. On Android a non-exportable AES-GCM wrapping key lives in Keystore (StrongBox when available), with per-use `BIOMETRIC_STRONG` via a `BiometricPrompt.CryptoObject`. Enrolling a new face or fingerprint destroys the key; the user then restores with the recovery phrase.
- **`LocalAuthKeyRelease`.** A `local_auth` prompt followed by `flutter_secure_storage`. The check is a boolean in app code, so it is weaker on jailbroken or rooted devices.
- **Database keys.** SQLCipher is keyed with raw 32-byte keys using `x'<hex>'`, so there is no PBKDF2 cost at unlock. Opening fails closed if `PRAGMA cipher_version` is empty.
- **Key handling.** The master key is wiped right after HKDF. The derived keys are separated by purpose: `sqlcipher`, `behavior`, `sync`.

## Integration

- **Dependency.** In the app's `pubspec.yaml`, add `privovault_crypto: { path: packages/privovault_crypto }`. Don't add `sqflite` or `sqlite3_flutter_libs`: a second SQLite build can load the plaintext one.
- **Android.** The host activity must be a `FlutterFragmentActivity`. `minSdk` is 23 or higher.
- **iOS.** The deployment target is 15.0 or higher. Add `NSFaceIDUsageDescription` to `Info.plist`.
- **Registration.** The plugin registers through `GeneratedPluginRegistrant`, so no manual wiring is needed.

## Tests

```bash
cd packages/privovault_crypto && flutter test
```

These tests cover the HLC, raw-key literal, SQL splitting, schema, AEAD, key derivation and the recovery phrase. The native key release must be tested on a device.
