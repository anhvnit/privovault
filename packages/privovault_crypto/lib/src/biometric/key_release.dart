import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/error_codes.dart' as auth_error;
import 'package:local_auth/local_auth.dart';

enum Biometry { faceId, touchId, opticId, fingerprint, face, none }

/// Typed failure modes surfaced by the native key bridges.
enum KeyFailure {
  cancelled, // user dismissed the prompt
  lockout, // too many attempts; OS passcode required
  invalidated, // biometrics re-enrolled → hardware key destroyed → use recovery phrase
  notEnrolled, // no FaceID/fingerprint set up
  unavailable, // no secure hardware
  notFound, // no master key stored on this device
  unknown,
}

class VaultKeyException implements Exception {
  VaultKeyException(this.failure, [this.message]);
  final KeyFailure failure;
  final String? message;
  @override
  String toString() => 'VaultKeyException(${failure.name}${message == null ? '' : ': $message'})';
}

/// How the 256-bit Master Key is released after biometric authentication.
///
/// Two interchangeable strategies:
///
/// * [HardwareBoundKeyRelease] (DEFAULT) — the OS secure hardware itself
///   refuses to release the key unless a live biometric match just happened
///   (Keychain `.biometryCurrentSet` / Keystore CryptoObject). Cryptographic
///   binding: a patched app or a rooted phone cannot skip the check.
///
/// * [LocalAuthKeyRelease] — `local_auth` prompt, then read the key from
///   flutter_secure_storage. Simple and fully Dart-side, but the binding is a
///   boolean in app code: on a jailbroken/rooted device, or with a hooked
///   `authenticate()`, the key can be read without biometrics. Use only if
///   you accept that threat model.
///
/// Choose the strategy when constructing [VaultHandshake].
abstract class KeyRelease {
  Future<({bool hasKey, Biometry biometry})> status();
  Future<Uint8List> createMasterKey({required String reason});
  Future<Uint8List> unlockMasterKey({required String reason});
  Future<void> importMasterKey(Uint8List mk, {required String reason});
  Future<void> destroy();
  Future<void> excludeFromBackup(String path);
}

/// Dart side of the biometric ↔ secure-hardware handshake.
///
/// iOS  (VaultKeyBridge.swift): MK in Keychain, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
///      + `SecAccessControl(.biometryCurrentSet)`. Reading the item *is* the FaceID prompt.
/// Android (VaultKeyBridge.kt): non-exportable AES-256-GCM key in Android Keystore
///      (StrongBox when present, `setUserAuthenticationRequired`, BIOMETRIC_STRONG,
///      invalidated on new enrollment). MK is stored wrapped by it in `noBackupFilesDir`;
///      unwrapping requires a BiometricPrompt CryptoObject.
///
/// The master key only exists in Dart memory between [unlock] and the
/// immediate HKDF derivation; callers must `wipe()` it.
class HardwareBoundKeyRelease implements KeyRelease {
  const HardwareBoundKeyRelease();
  static const _ch = MethodChannel('privovault_crypto/key_release');

  @override
  Future<({bool hasKey, Biometry biometry})> status() async {
    final m = await _ch.invokeMapMethod<String, Object?>('status');
    return (
      hasKey: m?['hasKey'] == true,
      biometry: Biometry.values.asNameMap()[m?['biometry']] ?? Biometry.none,
    );
  }

  /// Generates a fresh 256-bit MK in native code, stores it behind biometrics,
  /// and returns a copy for first-time setup (deriving keys + recovery wrap).
  @override
  Future<Uint8List> createMasterKey({required String reason}) =>
      _bytes('create', {'reason': reason});

  /// Biometric prompt → MK bytes.
  @override
  Future<Uint8List> unlockMasterKey({required String reason}) =>
      _bytes('unlock', {'reason': reason});

  /// Store an MK recovered from the 12-word phrase on a new device.
  @override
  Future<void> importMasterKey(Uint8List mk, {required String reason}) =>
      _guard(() => _ch.invokeMethod<void>('import', {'key': mk, 'reason': reason}));

  @override
  Future<void> destroy() => _guard(() => _ch.invokeMethod<void>('destroy'));

  /// Marks the vault directory as excluded from iCloud/iTunes backup (iOS).
  @override
  Future<void> excludeFromBackup(String path) =>
      _guard(() => _ch.invokeMethod<void>('excludeFromBackup', {'path': path}));

  Future<Uint8List> _bytes(String method, Map<String, Object?> args) async {
    final r = await _guard(() => _ch.invokeMethod<Uint8List>(method, args));
    if (r == null || r.length != 32) throw VaultKeyException(KeyFailure.unknown, 'bad key length');
    // StandardMessageCodec hands back an unmodifiable view; copy into a
    // buffer we own so it can be zeroed after key derivation.
    return Uint8List.fromList(r);
  }

  Future<T> _guard<T>(Future<T> Function() f) async {
    try {
      return await f();
    } on PlatformException catch (e) {
      throw VaultKeyException(KeyFailure.values.asNameMap()[e.code] ?? KeyFailure.unknown, e.message);
    }
  }
}

// ======================================================================
// local_auth strategy
// ======================================================================

/// `local_auth` + flutter_secure_storage. See [KeyRelease] for the caveat.
///
/// iOS item: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly (no backup,
/// no iCloud sync). Android: flutter_secure_storage v10 AES-GCM storage with
/// a Keystore RSA-OAEP-wrapped key (NOT user-authentication-bound).
class LocalAuthKeyRelease implements KeyRelease {
  LocalAuthKeyRelease({LocalAuthentication? auth, FlutterSecureStorage? storage})
      : _auth = auth ?? LocalAuthentication(),
        _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                // Deprecated in v10 but still read: `true` tells the plugin the
                // existing v9 values live in EncryptedSharedPreferences, and
                // migrateOnAlgorithmChange moves them to the new cipher on
                // first access. Removing it would orphan the stored key.
                // ignore: deprecated_member_use
                encryptedSharedPreferences: true,
                migrateOnAlgorithmChange: true,
                // v10 defaults to true (wipe ALL values on any read error).
                // This slot holds the master key: fail loudly instead.
                resetOnError: false,
              ),
              iOptions: IOSOptions(accessibility: KeychainAccessibility.passcode, synchronizable: false),
            );

  final LocalAuthentication _auth;
  final FlutterSecureStorage _storage;
  static const _slot = 'qlv.mk.v1';

  @override
  Future<({bool hasKey, Biometry biometry})> status() async {
    final types = await BiometricGate(_auth).available();
    return (hasKey: await _storage.containsKey(key: _slot), biometry: types);
  }

  @override
  Future<Uint8List> createMasterKey({required String reason}) async {
    await BiometricGate(_auth).require(reason);
    final mk = randomKey32();
    await _storage.write(key: _slot, value: base64Encode(mk));
    return mk;
  }

  @override
  Future<Uint8List> unlockMasterKey({required String reason}) async {
    await BiometricGate(_auth).require(reason);
    final v = await _storage.read(key: _slot);
    if (v == null) throw VaultKeyException(KeyFailure.notFound);
    return base64Decode(v);
  }

  @override
  Future<void> importMasterKey(Uint8List mk, {required String reason}) async {
    await BiometricGate(_auth).require(reason);
    await _storage.write(key: _slot, value: base64Encode(mk));
  }

  @override
  Future<void> destroy() => _storage.delete(key: _slot);

  @override
  Future<void> excludeFromBackup(String path) => const HardwareBoundKeyRelease().excludeFromBackup(path);
}

/// `local_auth` wrapper used in BOTH strategies for step-up confirmation of
/// sensitive actions while the vault is already open (show Emergency Kit,
/// Add/Revoke Staff, export reports). Biometric only, no passcode fallback.
class BiometricGate {
  BiometricGate([LocalAuthentication? auth]) : _auth = auth ?? LocalAuthentication();
  final LocalAuthentication _auth;

  Future<Biometry> available() async {
    if (!await _auth.isDeviceSupported() || !await _auth.canCheckBiometrics) return Biometry.none;
    final t = await _auth.getAvailableBiometrics();
    if (t.contains(BiometricType.face)) return Biometry.face;
    if (t.contains(BiometricType.fingerprint)) return Biometry.fingerprint;
    if (t.contains(BiometricType.strong)) return Biometry.fingerprint;
    return Biometry.none;
  }

  /// Throws [VaultKeyException] unless the user passes biometrics now.
  Future<void> require(String reason) async {
    try {
      final ok = await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true, // survive app switching mid-prompt
          sensitiveTransaction: true,
          useErrorDialogs: true,
        ),
      );
      if (!ok) throw VaultKeyException(KeyFailure.cancelled);
    } on PlatformException catch (e) {
      throw VaultKeyException(switch (e.code) {
        auth_error.notEnrolled => KeyFailure.notEnrolled,
        auth_error.passcodeNotSet => KeyFailure.notEnrolled,
        auth_error.lockedOut || auth_error.permanentlyLockedOut => KeyFailure.lockout,
        auth_error.notAvailable => KeyFailure.unavailable,
        _ => KeyFailure.unknown,
      }, e.message);
    }
  }
}

Uint8List randomKey32() {
  final r = Random.secure();
  return Uint8List.fromList(List<int>.generate(32, (_) => r.nextInt(256)));
}
