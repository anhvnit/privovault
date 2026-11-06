import 'dart:convert';
import 'dart:typed_data';

import '../roles.dart';

/// Everything a staff device needs, received from the owner during pairing.
/// Stored only inside `staff_credentials.qlc` (AES-GCM, key derived from the
/// staff device's own biometric-protected master key).
class StaffCredentials {
  StaffCredentials({
    required this.vaultId,
    required this.staffId,
    required this.displayName,
    required this.householdKey,
    required this.keyEpoch,
    required this.ownerPublicKey,
    required this.ownerSigningKey,
    required this.staffSecretKey,
    required this.staffPublicKey,
    required this.staffSigningSeed,
    required this.cloud,
    required this.capabilities,
  });

  final String vaultId;
  final String staffId; // == this device's id
  final String displayName;
  final Uint8List householdKey; // K_shared root for current epoch
  final int keyEpoch;
  final Uint8List ownerPublicKey; // X25519, key agreement for key-ring updates
  final Uint8List ownerSigningKey; // Ed25519 public, verifies owner packages + key-ring
  final Uint8List staffSecretKey; // X25519, generated on this device
  final Uint8List staffPublicKey;
  final Uint8List staffSigningSeed; // Ed25519 seed, signs this device's packages
  final CloudGrant cloud;
  final StaffCapabilities capabilities;

  /// Paired before the household space was separated from the owner's
  /// packages: its cloud token is an owner-app token. Such a phone never
  /// syncs any more and must be paired again (see [CloudGrant.separated]).
  bool get isLegacyPairing => !cloud.separated;

  StaffCredentials copyWith({Uint8List? householdKey, int? keyEpoch, CloudGrant? cloud, StaffCapabilities? capabilities}) =>
      StaffCredentials(
        vaultId: vaultId,
        staffId: staffId,
        displayName: displayName,
        householdKey: householdKey ?? this.householdKey,
        keyEpoch: keyEpoch ?? this.keyEpoch,
        ownerPublicKey: ownerPublicKey,
        ownerSigningKey: ownerSigningKey,
        staffSecretKey: staffSecretKey,
        staffPublicKey: staffPublicKey,
        staffSigningSeed: staffSigningSeed,
        cloud: cloud ?? this.cloud,
        capabilities: capabilities ?? this.capabilities,
      );

  Map<String, dynamic> toJson() => {
        'vault_id': vaultId,
        'staff_id': staffId,
        'name': displayName,
        'k_shared': base64Encode(householdKey),
        'epoch': keyEpoch,
        'owner_pk': base64Encode(ownerPublicKey),
        'owner_sig_pk': base64Encode(ownerSigningKey),
        'staff_sig_seed': base64Encode(staffSigningSeed),
        'staff_sk': base64Encode(staffSecretKey),
        'staff_pk': base64Encode(staffPublicKey),
        'cloud': cloud.toJson(),
        'caps': capabilities.toJson(),
      };

  factory StaffCredentials.fromJson(Map<String, dynamic> j) => StaffCredentials(
        vaultId: j['vault_id'] as String,
        staffId: j['staff_id'] as String,
        displayName: j['name'] as String,
        householdKey: base64Decode(j['k_shared'] as String),
        keyEpoch: j['epoch'] as int,
        ownerPublicKey: base64Decode(j['owner_pk'] as String),
        ownerSigningKey: base64Decode(j['owner_sig_pk'] as String),
        staffSigningSeed: base64Decode(j['staff_sig_seed'] as String),
        staffSecretKey: base64Decode(j['staff_sk'] as String),
        staffPublicKey: base64Decode(j['staff_pk'] as String),
        cloud: CloudGrant.fromJson(j['cloud'] as Map<String, dynamic>),
        capabilities: StaffCapabilities.fromJson(j['caps'] as Map<String, dynamic>),
      );
}

/// Delegated cloud access of a staff device.
///
/// Format 2 ([separated]): a token for the HOUSEHOLD space only (Google
/// `drive.file` grant; the second "PrivoVault Household" Dropbox / Azure
/// app) plus where this staff member's sub-folder is ([folder]) and the
/// household root holding the key-ring ([root]; Google folder id, '' for
/// Dropbox / OneDrive). It can't reach the owner's own packages.
///
/// Format 1 (no `fmt`): an owner-app token from older versions — reached
/// the owner's whole app folder. Kept parseable only so the phone can say
/// "pair again"; it is never used.
class CloudGrant {
  const CloudGrant({
    required this.provider,
    required this.refreshToken,
    required this.clientId,
    this.format = 1,
    this.root = '',
    this.folder = '',
  });
  final String provider; // 'gdrive' | 'onedrive' | 'dropbox'
  final String refreshToken;
  final String clientId;
  final int format;
  final String root;
  final String folder;

  static const householdFormat = 2;

  bool get separated => format >= householdFormat && folder.isNotEmpty;

  Map<String, dynamic> toJson() => {
        'provider': provider,
        'rt': refreshToken,
        'client_id': clientId,
        if (format != 1) 'fmt': format,
        if (format != 1) 'root': root,
        if (format != 1) 'folder': folder,
      };

  factory CloudGrant.fromJson(Map<String, dynamic> j) => CloudGrant(
        provider: j['provider'] as String,
        refreshToken: j['rt'] as String,
        clientId: j['client_id'] is String ? j['client_id'] as String : '',
        format: j['fmt'] is int ? j['fmt'] as int : 1,
        root: j['root'] is String ? j['root'] as String : '',
        folder: j['folder'] is String ? j['folder'] as String : '',
      );
}
