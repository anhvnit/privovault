import 'dart:convert';
import 'dart:typed_data';

import 'aead.dart';
import 'bip39_vendored.dart';
import 'keys.dart';

/// 12-word BIP-39 recovery phrase (128 bits of entropy).
///
/// The phrase never encrypts data directly. It derives a Recovery Key that
/// wraps the Master Key; the wrapped MK travels inside every sync package
/// header. Restoring on any OS = download package → enter 12 words →
/// unwrap MK → derive keys → open vault. The phrase is never stored.
abstract final class RecoveryPhrase {
  static String generate() => Bip39.generateMnemonic(strengthBits: 128);

  static String normalize(String m) =>
      m.trim().toLowerCase().split(RegExp(r'\s+')).where((w) => w.isNotEmpty).join(' ');

  static bool isValid(String m) {
    final n = normalize(m);
    return n.split(' ').length == 12 && Bip39.validateMnemonic(n);
  }

  static List<int> _aad(String vaultId) => utf8.encode('qlv-recovery|$vaultId|v1');

  /// 128-bit entropy → HKDF → 256-bit Recovery Key. The entropy is already
  /// uniformly random (CSPRNG), so a slow KDF adds nothing here.
  static Future<Uint8List> _recoveryKey(String mnemonic, String vaultId) async {
    final n = normalize(mnemonic);
    // Same entropy bytes the bip39 package returned (hex) for every valid phrase.
    final Uint8List entropy;
    try {
      entropy = Bip39.mnemonicToEntropy(n);
    } on FormatException {
      throw const FormatException('Invalid recovery phrase');
    }
    try {
      return await hkdf(entropy, salt: utf8.encode(vaultId), info: utf8.encode('qlv/recovery/v1'));
    } finally {
      wipe(entropy);
    }
  }

  /// Returns base64(nonce || AES-GCM(MK) || tag).
  static Future<String> wrapMasterKey(Uint8List mk, String mnemonic, String vaultId) async {
    final rk = await _recoveryKey(mnemonic, vaultId);
    try {
      return base64Encode(await Aead.seal(rk, mk, aad: _aad(vaultId)));
    } finally {
      wipe(rk);
    }
  }

  /// Throws if the phrase is wrong (GCM authentication fails).
  static Future<Uint8List> unwrapMasterKey(String wrappedB64, String mnemonic, String vaultId) async {
    final rk = await _recoveryKey(mnemonic, vaultId);
    try {
      return await Aead.open(rk, base64Decode(wrappedB64), aad: _aad(vaultId));
    } finally {
      wipe(rk);
    }
  }
}
