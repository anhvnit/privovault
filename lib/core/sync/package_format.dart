import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/aead.dart';
import '../db/vault_database.dart';

/// `.qlv` zero-knowledge sync package — one file per (scope, device).
///
/// ```
/// "QLV1" | u32 headerLen | header(JSON, UTF-8) | u16 sigLen | Ed25519 sig | body
///   sig  = Ed25519(signer, "QLV1" ‖ header ‖ SHA-256(body))
///   body = AES-256-GCM(K_scope.sync, plaintext, aad = header)
///   plaintext = u32 len ‖ SQLCipher snapshot ‖ u32 len ‖ behavior blob (already AES-GCM sealed, or empty)
/// ```
///
/// What the cloud provider (and a staff member holding only K_shared) can
/// see: file name, size (padded to 64 KiB buckets), and the header fields
/// below. No amounts, names, categories or counts — those are all inside
/// the AES-GCM body, which is itself a SQLCipher file (two layers).
class PackageHeader {
  const PackageHeader({
    required this.scope,
    required this.vaultId,
    required this.deviceId,
    required this.signer,
    required this.schemaVersion,
    required this.createdAt,
    required this.maxHlc,
    required this.bodySha256,
    this.keyEpoch,
    this.wrappedMasterKey,
  });

  final DataScope scope;
  final String vaultId;
  final String deviceId;
  final String signer; // 'owner' | 'staff'
  final int schemaVersion;
  final int createdAt;
  final String maxHlc;
  final String bodySha256; // base64
  final int? keyEpoch; // shared scope: which household key epoch
  final String? wrappedMasterKey; // private scope: MK wrapped by the recovery phrase

  Map<String, Object?> toJson() => {
        'fmt': 1,
        'scope': scope.name,
        'vault_id': vaultId,
        'device_id': deviceId,
        'signer': signer,
        'schema': schemaVersion,
        'created_at': createdAt,
        'max_hlc': maxHlc,
        'body_sha256': bodySha256,
        if (keyEpoch != null) 'key_epoch': keyEpoch,
        if (wrappedMasterKey != null) 'wrapped_mk': wrappedMasterKey,
      };

  factory PackageHeader.fromJson(Map<String, dynamic> j) {
    if (j['fmt'] != 1) throw const FormatException('Unsupported package format');
    return PackageHeader(
      scope: DataScope.values.byName(j['scope'] as String),
      vaultId: j['vault_id'] as String,
      deviceId: j['device_id'] as String,
      signer: j['signer'] as String,
      schemaVersion: j['schema'] as int,
      createdAt: j['created_at'] as int,
      maxHlc: j['max_hlc'] as String,
      bodySha256: j['body_sha256'] as String,
      keyEpoch: j['key_epoch'] as int?,
      wrappedMasterKey: j['wrapped_mk'] as String?,
    );
  }
}

class PackageContents {
  PackageContents({required this.header, required this.database, this.behaviorSealed});
  final PackageHeader header;
  final Uint8List database; // SQLCipher file bytes (still encrypted with the scope's SQLCipher key)
  final Uint8List? behaviorSealed;
}

class PackageTampered implements Exception {
  PackageTampered(this.reason);
  final String reason;
  @override
  String toString() => 'PackageTampered: $reason';
}

/// Structurally invalid package (truncated, bad lengths, unparsable header,
/// wrong field types). A subtype of [PackageTampered] so every caller that
/// already skips tampered files skips these too.
class PackageMalformed extends PackageTampered {
  PackageMalformed(super.reason);
  @override
  String toString() => 'PackageMalformed: $reason';
}

/// Parsed but not yet verified/decrypted package (header is readable so the
/// engine can choose keys and skip unchanged files cheaply).
class SealedPackage {
  SealedPackage._(this.header, this._headerBytes, this._signature, this._body);

  final PackageHeader header;
  final Uint8List _headerBytes;
  final Uint8List _signature;
  final Uint8List _body;

  static const _magic = [0x51, 0x4C, 0x56, 0x31]; // "QLV1"
  static const _bucket = 64 * 1024;

  // ---------------------------------------------------------------- build

  static Future<Uint8List> build({
    required PackageHeader Function(String bodySha256) header,
    required Uint8List syncKey,
    required Uint8List signingSeed,
    required Uint8List database,
    Uint8List? behaviorSealed,
  }) async {
    final plain = BytesBuilder(copy: false)
      ..add(_u32(database.length))
      ..add(database)
      ..add(_u32(behaviorSealed?.length ?? 0))
      ..add(behaviorSealed ?? const <int>[]);
    // Pad plaintext to a bucket boundary so size leaks only coarse growth.
    final raw = plain.takeBytes();
    final padded = Uint8List(((raw.length + 4) ~/ _bucket + 1) * _bucket)
      ..setRange(0, raw.length, raw);

    // The body hash depends on the ciphertext, so the AAD is the header with
    // an empty `body_sha256`; the complete header (with hash) is then signed.
    final aadHeader = header('');
    final aad = utf8.encode(jsonEncode(aadHeader.toJson()));
    final body = await Aead.seal(syncKey, padded, aad: aad);
    final h = header(base64Encode(await sha256(body)));
    final headerBytes = Uint8List.fromList(utf8.encode(jsonEncode(h.toJson())));

    final kp = await Ed25519().newKeyPairFromSeed(signingSeed);
    final sig = await Ed25519().sign(await _signedMessage(headerBytes, body), keyPair: kp);

    return (BytesBuilder(copy: false)
          ..add(_magic)
          ..add(_u32(headerBytes.length))
          ..add(headerBytes)
          ..add(_u16(sig.bytes.length))
          ..add(sig.bytes)
          ..add(body))
        .takeBytes();
  }

  // ---------------------------------------------------------------- parse

  /// Upper bound for the JSON header (real headers are < 1 KiB; the
  /// private one carries a wrapped master key, still far below this).
  static const _maxHeaderLen = 64 * 1024;
  static const _sigLen = 64; // Ed25519

  /// Parses the framing and header. Never throws anything but
  /// [PackageTampered] / [PackageMalformed] for bad input.
  static SealedPackage parse(Uint8List bytes) {
    if (bytes.length < 10 || !_eq(Uint8List.sublistView(bytes, 0, 4), _magic)) throw PackageMalformed('bad magic');
    final bd = ByteData.sublistView(bytes);
    final hLen = bd.getUint32(4);
    if (hLen == 0 || hLen > _maxHeaderLen) throw PackageMalformed('bad header length');
    if (8 + hLen + 2 > bytes.length) throw PackageMalformed('truncated header');
    final headerBytes = Uint8List.sublistView(bytes, 8, 8 + hLen);
    final sLen = bd.getUint16(8 + hLen);
    if (sLen != _sigLen) throw PackageMalformed('bad signature length');
    final sigStart = 10 + hLen;
    if (sigStart + sLen > bytes.length) throw PackageMalformed('truncated signature');
    final sig = Uint8List.sublistView(bytes, sigStart, sigStart + sLen);
    final body = Uint8List.sublistView(bytes, sigStart + sLen);
    if (body.length < Aead.nonceLength + Aead.tagLength) throw PackageMalformed('truncated body');
    final PackageHeader header;
    try {
      final j = jsonDecode(utf8.decode(headerBytes));
      if (j is! Map<String, dynamic>) throw PackageMalformed('header is not an object');
      header = PackageHeader.fromJson(j);
    } on PackageTampered {
      rethrow;
    } catch (_) {
      // FormatException (UTF-8 / JSON / fmt), TypeError (field types),
      // ArgumentError (unknown scope name)...
      throw PackageMalformed('unreadable header');
    }
    return SealedPackage._(header, headerBytes, sig, body);
  }

  /// Verify signature and body hash against the expected signer key.
  Future<void> verify(List<int> signerPublicKey) async {
    if (signerPublicKey.length != 32) throw PackageTampered('bad signer key');
    if (base64Encode(await sha256(_body)) != header.bodySha256) throw PackageTampered('body hash mismatch');
    final bool ok;
    try {
      ok = await Ed25519().verify(
        await _signedMessage(_headerBytes, _body),
        signature: Signature(_signature, publicKey: SimplePublicKey(signerPublicKey, type: KeyPairType.ed25519)),
      );
    } catch (_) {
      throw PackageTampered('signature invalid');
    }
    if (!ok) throw PackageTampered('signature invalid');
  }

  /// Decrypt (AES-GCM authenticates body + header). Call [verify] first
  /// whenever the signer key is known.
  Future<PackageContents> open(Uint8List syncKey) async {
    final aadHeader = Map<String, Object?>.of(header.toJson())..['body_sha256'] = '';
    final Uint8List plain;
    try {
      plain = await Aead.open(syncKey, _body, aad: utf8.encode(jsonEncode(aadHeader)));
    } on ArgumentError {
      rethrow; // wrong key length: a programming error, not bad input
    } catch (_) {
      // SecretBoxAuthenticationError (wrong key / altered body or header),
      // FormatException (too short).
      throw PackageTampered('decryption failed');
    }
    if (plain.length < 8) throw PackageMalformed('truncated plaintext');
    final bd = ByteData.sublistView(plain);
    final dbLen = bd.getUint32(0);
    if (dbLen > plain.length - 8) throw PackageMalformed('bad database length');
    final db = Uint8List.sublistView(plain, 4, 4 + dbLen);
    final bLen = bd.getUint32(4 + dbLen);
    if (bLen > plain.length - 8 - dbLen) throw PackageMalformed('bad behavior length');
    final beh = bLen == 0 ? null : Uint8List.sublistView(plain, 8 + dbLen, 8 + dbLen + bLen);
    return PackageContents(header: header, database: db, behaviorSealed: beh);
  }

  static Future<List<int>> _signedMessage(Uint8List headerBytes, Uint8List body) async =>
      [..._magic, ...headerBytes, ...await sha256(body)];

  static Uint8List _u32(int v) => Uint8List(4)..buffer.asByteData().setUint32(0, v);
  static Uint8List _u16(int v) => Uint8List(2)..buffer.asByteData().setUint16(0, v);
  static bool _eq(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
