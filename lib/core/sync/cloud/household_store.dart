import 'dart:typed_data';

import 'cloud_store.dart';
import 'dropbox_app_folder.dart';
import 'google_drive_household.dart';
import 'oauth.dart';
import 'onedrive_approot.dart';

// ======================================================================
// Household space
// ======================================================================
//
// Staff channels live in a cloud space SEPARATE from the owner's own
// packages, so no token a staff phone holds can reach `ql.private.*`:
//
//   provider   space (own OAuth grant / app)        per-staff folder
//   gdrive     My Drive "PrivoVault Household/"     <staffId>/  (folder id)
//              scope drive.file only
//   dropbox    /Apps/PrivoVault Household           /<staffId>  (path)
//              second Dropbox app
//   onedrive   Apps/PrivoVault Household            <staffId>   (name)
//              second Azure app registration
//
// Root of the space: the key-ring (`ql.keyring.qlk`) and the owner-signed
// "moved" marker. Each staff sub-folder: `staff_<id>.db` (staff writes) and
// `staff_<id>.owner.db` (owner writes).
//
// Owner devices hold their own household token (OwnerTokenStore.household)
// and read/write every channel through [HouseholdCloudStore.owner]. Staff
// phones get [HouseholdCloudStore.staff]: the root (by exact name only) and
// their OWN sub-folder; any other staff id resolves to nothing.

/// The OWNER's household sign-in expired or was revoked. Distinct from
/// [CloudAuthExpired] on the owner's home cloud: only the household part of
/// a sync stops, the owner's own packages keep syncing.
class HouseholdAuthExpired extends CloudAuthExpired {
  @override
  String toString() => 'Household cloud authorisation expired or revoked; sign in again.';
}

/// One staff sub-folder. [ref] is what staff credentials carry (Google:
/// folder id; Dropbox: `/<name>`; OneDrive: `<name>`); [id] is the
/// provider's item id used to delete it.
class HouseholdFolder {
  const HouseholdFolder({required this.name, required this.ref, required this.id});
  final String name;
  final String ref;
  final String id;
}

/// A [CloudStore] over the household root, plus per-staff sub-folders.
/// Create one per sync pass (folder lookups are cached for its lifetime).
class HouseholdCloudStore implements CloudStore {
  HouseholdCloudStore._(this._b, {required bool ownerSide, String? onlyStaffId, String? onlyStaffRef})
      : _ownerSide = ownerSide,
        _onlyStaff = onlyStaffId {
    if (onlyStaffId != null && onlyStaffRef != null) _refs[onlyStaffId] = onlyStaffRef;
  }

  /// Owner devices: the whole household space.
  factory HouseholdCloudStore.owner(String provider, AuthedHttp http, {required String rootRef}) =>
      HouseholdCloudStore._(_backend(provider, http, rootRef), ownerSide: true);

  /// A staff phone: the root (key-ring, moved marker) and ITS sub-folder.
  factory HouseholdCloudStore.staff({
    required String provider,
    required AuthedHttp http,
    required String staffId,
    required String rootRef,
    required String folderRef,
  }) =>
      HouseholdCloudStore._(_backend(provider, http, rootRef),
          ownerSide: false, onlyStaffId: staffId, onlyStaffRef: folderRef);

  /// Owner, when connecting: make sure the household root exists and return
  /// its [rootRef] (Google: id of "PrivoVault Household" in My Drive, found
  /// or created; Dropbox / OneDrive: '' — the household app folder).
  static Future<String> prepareRoot(String provider, AuthedHttp http) async {
    if (provider != 'gdrive') return '';
    return await GoogleDriveFolderStore.findFolder(http, GoogleDriveFolderStore.rootFolderName) ??
        await GoogleDriveFolderStore.createFolder(http, GoogleDriveFolderStore.rootFolderName);
  }

  /// Providers a household space can use (never iCloud).
  static const providers = ['gdrive', 'onedrive', 'dropbox'];

  static _Backend _backend(String provider, AuthedHttp http, String rootRef) => switch (provider) {
        'gdrive' => _GoogleBackend(http, rootRef),
        'dropbox' => _DropboxBackend(http),
        'onedrive' => _OneDriveBackend(http),
        _ => throw ArgumentError('Household space unavailable on $provider'),
      };

  final _Backend _b;
  final bool _ownerSide;
  final String? _onlyStaff;
  final Map<String, String> _refs = {};

  /// Where the root lives, as staff credentials carry it.
  String get rootRef => _b.rootRef;

  /// The root of the space: key-ring and moved marker.
  /// Staff: listing limited to `ql.keyring.*`, exact-name stat / download,
  /// no writes (only owner devices write the root).
  late final CloudStore root = _ownerSide ? _OwnerGuarded(_b.rootFiles) : _StaffRoot(_b.rootFiles);

  /// [staffId]'s sub-folder, or null when it doesn't exist (owner: created
  /// first when [create]). A staff store resolves only its own id.
  Future<CloudStore?> staffFolder(String staffId, {bool create = false}) async {
    final ref = await _ref(staffId, create: create);
    return ref == null ? null : _wrap(_b.files(ref));
  }

  /// Owner: [staffId]'s folder reference for its credentials (created).
  Future<String> folderRef(String staffId) async {
    final ref = await _ref(staffId, create: true);
    if (ref == null) throw StateError('Household folder unavailable');
    return ref;
  }

  Future<String?> _ref(String staffId, {required bool create}) async {
    if (_onlyStaff != null) return staffId == _onlyStaff ? _refs[staffId] : null;
    final cached = _refs[staffId];
    if (cached != null) return cached;
    var ref = await _guard(() => _b.findFolder(staffId));
    if (ref == null && create) ref = await _guard(() => _b.createFolder(staffId));
    if (ref != null) _refs[staffId] = ref;
    return ref;
  }

  /// Owner: every sub-folder in the space (name = staff id, if ours).
  Future<List<HouseholdFolder>> staffFolders() {
    if (!_ownerSide) throw StateError('Staff devices never list the household space');
    return _guard(_b.listFolders);
  }

  /// Owner: delete a sub-folder with everything in it.
  Future<void> deleteStaffFolder(HouseholdFolder f) {
    if (!_ownerSide) throw StateError('Staff devices never delete household folders');
    _refs.remove(f.name);
    return _guard(() => _b.deleteFolder(f));
  }

  CloudStore _wrap(CloudStore s) => _ownerSide ? _OwnerGuarded(s) : s;

  Future<T> _guard<T>(Future<T> Function() op) => _ownerSide ? _ownerGuard(op) : op();

  // ----------------------------------------------- CloudStore (= the root)

  @override
  String get providerId => _b.providerId;

  /// Owner: any listing of the root. Staff: ONLY the key-rings
  /// (`ql.keyring.*`, one per owner device, written by owners via [put]);
  /// any other prefix lists nothing — staff use exact names.
  static const staffListablePrefix = 'ql.keyring.';

  @override
  Future<List<RemoteObject>> list({String prefix = 'ql.'}) async {
    if (!_ownerSide && !prefix.startsWith(staffListablePrefix)) return const [];
    return root.list(prefix: prefix);
  }

  @override
  Future<RemoteObject?> stat(String name) => root.stat(name);

  @override
  Future<Uint8List> download(RemoteObject o) => root.download(o);

  @override
  Future<RemoteObject> put(String name, Uint8List bytes, {RemoteObject? existing}) =>
      root.put(name, bytes, existing: existing);

  @override
  Future<void> delete(RemoteObject o) => root.delete(o);

  @override
  Future<void> deletePermanently(RemoteObject o) => root.deletePermanently(o);
}

Future<T> _ownerGuard<T>(Future<T> Function() op) async {
  try {
    return await op();
  } on HouseholdAuthExpired {
    rethrow;
  } on CloudAuthExpired {
    throw HouseholdAuthExpired();
  }
}

/// Maps the household token's [CloudAuthExpired] to [HouseholdAuthExpired]
/// on owner devices.
class _OwnerGuarded implements CloudStore {
  _OwnerGuarded(this._s);
  final CloudStore _s;

  @override
  String get providerId => _s.providerId;
  @override
  Future<List<RemoteObject>> list({String prefix = 'ql.'}) => _ownerGuard(() => _s.list(prefix: prefix));
  @override
  Future<RemoteObject?> stat(String name) => _ownerGuard(() => _s.stat(name));
  @override
  Future<Uint8List> download(RemoteObject o) => _ownerGuard(() => _s.download(o));
  @override
  Future<RemoteObject> put(String name, Uint8List bytes, {RemoteObject? existing}) =>
      _ownerGuard(() => _s.put(name, bytes, existing: existing));
  @override
  Future<void> delete(RemoteObject o) => _ownerGuard(() => _s.delete(o));
  @override
  Future<void> deletePermanently(RemoteObject o) => _ownerGuard(() => _s.deletePermanently(o));
}

/// The household root as a STAFF phone sees it: key-rings may be listed,
/// any other name only by exact [stat]; nothing is written or deleted.
class _StaffRoot implements CloudStore {
  _StaffRoot(this._s);
  final CloudStore _s;

  @override
  String get providerId => _s.providerId;
  @override
  Future<List<RemoteObject>> list({String prefix = 'ql.'}) async {
    if (!prefix.startsWith(HouseholdCloudStore.staffListablePrefix)) return const [];
    return _s.list(prefix: prefix);
  }

  @override
  Future<RemoteObject?> stat(String name) => _s.stat(name);
  @override
  Future<Uint8List> download(RemoteObject o) => _s.download(o);
  @override
  Future<RemoteObject> put(String name, Uint8List bytes, {RemoteObject? existing}) async =>
      throw StateError('Staff devices never write the household root');
  @override
  Future<void> delete(RemoteObject o) async => throw StateError('Staff devices never delete in the household root');
  @override
  Future<void> deletePermanently(RemoteObject o) => delete(o);
}

// ------------------------------------------------------------- backends

abstract class _Backend {
  String get providerId;
  String get rootRef;
  CloudStore get rootFiles;
  CloudStore files(String ref);
  Future<String?> findFolder(String name);
  Future<String> createFolder(String name);
  Future<List<HouseholdFolder>> listFolders();
  Future<void> deleteFolder(HouseholdFolder f);
}

class _GoogleBackend implements _Backend {
  _GoogleBackend(this._http, this.rootRef) {
    if (rootRef.isEmpty) throw StateError('Household folder id missing');
  }
  final AuthedHttp _http;
  @override
  final String rootRef;

  @override
  String get providerId => 'gdrive';
  @override
  CloudStore get rootFiles => GoogleDriveFolderStore(_http, rootRef);
  @override
  CloudStore files(String ref) => GoogleDriveFolderStore(_http, ref);
  @override
  Future<String?> findFolder(String name) => GoogleDriveFolderStore.findFolder(_http, name, parentId: rootRef);
  @override
  Future<String> createFolder(String name) => GoogleDriveFolderStore.createFolder(_http, name, parentId: rootRef);
  @override
  Future<List<HouseholdFolder>> listFolders() async => [
        for (final f in await GoogleDriveFolderStore.listFolders(_http, rootRef))
          HouseholdFolder(name: f.name, ref: f.id, id: f.id),
      ];
  @override
  Future<void> deleteFolder(HouseholdFolder f) => GoogleDriveFolderStore.deleteById(_http, f.id);
}

class _DropboxBackend implements _Backend {
  _DropboxBackend(this._http) : _root = DropboxAppFolderStore(_http);
  final AuthedHttp _http;
  final DropboxAppFolderStore _root;

  @override
  String get providerId => 'dropbox';
  @override
  String get rootRef => '';
  @override
  CloudStore get rootFiles => _root;
  @override
  CloudStore files(String ref) => DropboxAppFolderStore(_http, folder: _safePath(ref));
  // Path-addressed: a missing folder simply reads as empty, and uploads
  // create it, so no lookup is needed.
  @override
  Future<String?> findFolder(String name) async => '/$name';
  @override
  Future<String> createFolder(String name) async {
    await _root.createFolder(name);
    return '/$name';
  }

  @override
  Future<List<HouseholdFolder>> listFolders() async => [
        for (final f in await _root.listFolders()) HouseholdFolder(name: f.name, ref: f.path, id: f.path),
      ];
  @override
  Future<void> deleteFolder(HouseholdFolder f) => _root.deleteFolder(f.id);

  /// One level below the app folder, nothing else.
  static String _safePath(String ref) {
    if (!RegExp(r'^/[0-9A-Za-z-]{8,64}$').hasMatch(ref)) throw StateError('Invalid household folder');
    return ref;
  }
}

class _OneDriveBackend implements _Backend {
  _OneDriveBackend(this._http) : _root = OneDriveAppFolderStore(_http);
  final AuthedHttp _http;
  final OneDriveAppFolderStore _root;

  @override
  String get providerId => 'onedrive';
  @override
  String get rootRef => '';
  @override
  CloudStore get rootFiles => _root;
  @override
  CloudStore files(String ref) {
    if (!RegExp(r'^[0-9A-Za-z-]{8,64}$').hasMatch(ref)) throw StateError('Invalid household folder');
    return OneDriveAppFolderStore(_http, folder: ref);
  }

  @override
  Future<String?> findFolder(String name) async => name; // path-addressed (see Dropbox)
  @override
  Future<String> createFolder(String name) async {
    await _root.createFolder(name);
    return name;
  }

  @override
  Future<List<HouseholdFolder>> listFolders() async => [
        for (final f in await _root.listFolders()) HouseholdFolder(name: f.name, ref: f.name, id: f.id),
      ];
  @override
  Future<void> deleteFolder(HouseholdFolder f) => _root.deleteFolder(f.id);
}
