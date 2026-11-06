import 'dart:typed_data';

/// A file in the user's app-private cloud folder.
class RemoteObject {
  const RemoteObject({required this.id, required this.name, required this.version, required this.size, this.modified});
  final String id;
  final String name;

  /// Provider content fingerprint (Drive md5Checksum / OneDrive cTag).
  /// Equal version ⇒ identical bytes ⇒ skip download.
  final String version;
  final int size;
  final DateTime? modified;
}

class CloudAuthExpired implements Exception {
  @override
  String toString() => 'Cloud authorisation expired or revoked; sign in again.';
}

/// Minimal BYOC storage surface. Implementations talk only to the
/// provider's official API, inside the app-private folder, with the
/// narrowest scope that exists. No developer server is involved.
abstract class CloudStore {
  String get providerId; // 'gdrive' | 'onedrive'

  Future<List<RemoteObject>> list({String prefix = 'ql.'});

  /// Metadata of exactly [name], or null if absent — WITHOUT listing the
  /// folder. Staff devices use only this, so the client never even sees
  /// the names of other staff members' files.
  Future<RemoteObject?> stat(String name);
  Future<Uint8List> download(RemoteObject o);

  /// Create or overwrite [name]. Pass [existing] to update in place.
  Future<RemoteObject> put(String name, Uint8List bytes, {RemoteObject? existing});
  Future<void> delete(RemoteObject o);

  /// Delete [o] so that the provider keeps NO recoverable copy (no trash /
  /// recycle bin / version history), where the provider supports it; used
  /// when old ciphertext must really be gone (new Emergency Kit). Default =
  /// [delete]. Per provider:
  ///  * Google Drive: `files.delete` already bypasses the trash → permanent.
  ///  * OneDrive: Graph `permanentDelete`, falling back to [delete] (recycle
  ///    bin) where the account type does not offer it (personal accounts).
  ///  * Dropbox: `permanently_delete` exists for Business teams only, so this
  ///    is [delete]; Dropbox keeps the deleted file restorable for its
  ///    retention period (30–180 days by plan).
  ///  * iCloud Drive: [delete]; whether iCloud keeps a recoverable copy
  ///    ("Recently Deleted") is not under the app's control.
  /// Implementations must override it (every store `implements` this class).
  Future<void> deletePermanently(RemoteObject o) => delete(o);
}

/// Upper bounds on what any client downloads from the (shared, untrusted)
/// cloud folder. Anyone holding a folder token can plant files there; a
/// multi-GB `ql.shared.<x>.qlv` would otherwise be read fully into memory
/// on every sync pass and crash the app.
///
/// * Packages: a vault holds text rows only (no blobs); 30 MB is already a
///   very large vault, so 64 MiB leaves ample head-room.
/// * Markers (anchor / moved): a few hundred bytes of signed JSON.
/// * Key-ring: one wrapped key per staff member — kilobytes.
abstract final class CloudLimits {
  static const maxPackageBytes = 64 * 1024 * 1024;
  static const maxMarkerBytes = 64 * 1024;
  static const maxKeyRingBytes = 1024 * 1024;
}

/// A remote file is larger than the cap for its kind; it was not fetched.
class RemoteTooLarge implements Exception {
  const RemoteTooLarge(this.name, this.size, this.limit);
  final String name;
  final int size;
  final int limit;
  @override
  String toString() => 'Remote file $name too large ($size > $limit bytes)';
}

extension CappedDownload on CloudStore {
  /// [download] that refuses files whose listed size exceeds [limit]
  /// (checked BEFORE any byte is fetched) and, for providers that report
  /// no size (0), re-checks the downloaded length.
  Future<Uint8List> downloadCapped(RemoteObject o, int limit) async {
    if (o.size > limit) throw RemoteTooLarge(o.name, o.size, limit);
    final bytes = await download(o);
    if (bytes.length > limit) throw RemoteTooLarge(o.name, bytes.length, limit);
    return bytes;
  }
}
