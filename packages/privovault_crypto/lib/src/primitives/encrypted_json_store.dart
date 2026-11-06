import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'aead.dart';

/// A JSON document encrypted at rest with AES-256-GCM (used for
/// `behavior_profile.json`). Writes are atomic (temp file + rename).
class EncryptedJsonStore {
  EncryptedJsonStore({required this.file, required Uint8List key, required this.aadLabel}) : _key = key;

  final File file;
  final Uint8List _key;
  final String aadLabel;
  bool _wiped = false;

  List<int> get _aad => utf8.encode('qlv-json|$aadLabel|v1');

  /// Zero the key (vault locked). Every later load / save throws instead
  /// of reading or writing under a zeroed key.
  void wipeKey() {
    _wiped = true;
    wipe(_key);
  }

  bool get isWiped => _wiped;

  void _assertKey() {
    if (_wiped) throw StateError('Vault is locked');
  }

  /// The current document re-sealed under [newKey] (same AAD), or null when
  /// no file exists. Nothing is written; used by master-key rotation.
  Future<Uint8List?> resealFor(Uint8List newKey) async {
    _assertKey();
    if (!await file.exists()) return null;
    final clear = await Aead.open(_key, await file.readAsBytes(), aad: _aad);
    try {
      return await Aead.seal(newKey, clear, aad: _aad);
    } finally {
      wipe(clear);
    }
  }

  Future<Map<String, dynamic>> load() async {
    _assertKey();
    if (!await file.exists()) return <String, dynamic>{};
    final sealed = await file.readAsBytes();
    final clear = await Aead.open(_key, sealed, aad: _aad);
    return jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
  }

  Future<void> save(Map<String, dynamic> json) async {
    _assertKey();
    final sealed = await Aead.seal(_key, utf8.encode(jsonEncode(json)), aad: _aad);
    await file.parent.create(recursive: true);
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(sealed, flush: true);
    await tmp.rename(file.path);
  }

  /// Raw sealed bytes — for bundling into a sync package without decrypting.
  Future<Uint8List?> readSealed() async => await file.exists() ? file.readAsBytes() : null;

  /// Replace from sealed bytes (after verifying they decrypt).
  Future<void> writeSealed(Uint8List sealed) async {
    _assertKey();
    await Aead.open(_key, sealed, aad: _aad); // verify before overwrite
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(sealed, flush: true);
    await tmp.rename(file.path);
  }
}
