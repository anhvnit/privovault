/// Key-lifecycle values the handshake keeps in `vault_meta`.
///
/// Private file (owner only): secrets. Shared file: public values every
/// paired device may read. Applications add their own meta keys freely; these
/// names are reserved.
abstract final class CryptoMeta {
  static const householdEpoch = 'household_epoch';
  static String householdKey(int epoch) => 'household_key_e$epoch';

  /// Another key of the same household generation, known to this device
  /// (two owner devices created one for the same epoch; [householdKey]
  /// holds the agreed one). [fp] is a 16-hex-char public fingerprint. The
  /// owner unlock also tries these, so a shared.db still keyed with a
  /// superseded key opens after a crash before its re-key.
  static String householdKeyAlt(int epoch, String fp) => 'household_key_e${epoch}_alt_$fp';
  static const ownerSecretKey = 'owner_x25519_sk';
  static const ownerSigningSeed = 'owner_ed25519_seed';
  static const recoveryWrappedMk = 'recovery_wrapped_mk';

  /// Set (private file) when an owner unlock found shared.db missing and had
  /// to start a fresh, empty one. While set, the sync layer must merge this
  /// device's own cloud shared package BEFORE pushing shared data, so the
  /// empty file never overwrites the cloud copy. Value: ms timestamp.
  static const sharedDbRecreated = 'shared_db_recreated';
}

abstract final class SharedCryptoMeta {
  static const ownerPublicKey = 'owner_x25519_pk';
  static const ownerSigningKey = 'owner_ed25519_pk';
  static const vaultId = 'vault_id';
}

/// Biometric prompt texts, supplied (and localised) by the application.
class UnlockPrompts {
  const UnlockPrompts({
    required this.createVault,
    required this.unlockOwner,
    required this.unlockStaff,
    required this.secureDevice,
    required this.applyKeyUpdate,
    required this.protectRestored,
    this.rotateMasterKey = 'Protect your new vault key',
  });

  final String createVault;
  final String unlockOwner;
  final String unlockStaff;
  final String secureDevice;
  final String applyKeyUpdate;
  final String protectRestored;

  /// Shown when a replaced Master Key is stored behind biometrics.
  final String rotateMasterKey;

  static const english = UnlockPrompts(
    createVault: 'Create your private vault',
    unlockOwner: 'Unlock your vault',
    unlockStaff: 'Unlock household log',
    secureDevice: 'Secure this device',
    applyKeyUpdate: 'Apply household key update',
    protectRestored: 'Protect restored vault with biometrics',
  );
}
