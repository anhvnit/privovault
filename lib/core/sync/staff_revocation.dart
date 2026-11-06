import 'dart:convert';

import '../db/vault_database.dart';
import 'cloud/cloud_config.dart';
import 'cloud/cloud_store.dart' show CloudAuthExpired;
import 'cloud/oauth.dart';
import 'staff_channel.dart';

/// Outcome of revoking one staff member (owner). Every step that did not
/// complete is retried automatically on the next owner sync
/// ([StaffRevocation.resumePending], recomputed from
/// `staff_members.revoked_at` — no separate marker to lose).
class StaffRevokeResult {
  const StaffRevokeResult({
    required this.staffId,
    required this.recorded,
    required this.keyRetired,
    required this.keyRingPublished,
    required this.tokenRevoked,
    required this.tokenRevokeUnsupported,
    this.provider,
  });

  final String staffId;

  /// `revoked_at` is stored: from now on every package signed by that
  /// device's key is refused. False = nothing changed; ask to try again.
  final bool recorded;

  /// Per-staff channel key destroyed (or, on a vault still on the legacy
  /// household model, the household key rotated).
  final bool keyRetired;

  /// A key-ring listing the device as revoked was uploaded.
  final bool keyRingPublished;

  /// The provider confirmed the delegated refresh token was revoked (or
  /// there was no grant on this device).
  final bool tokenRevoked;

  /// The provider has no per-token revocation (OneDrive): the device can't
  /// decrypt anything new, but its household-space token keeps working until
  /// the owner removes the "PrivoVault Household" app's consent and re-issues
  /// access to the remaining staff ([StaffRevocation.reissuePending]). It
  /// never reaches the owner's own packages (separate app registration).
  final bool tokenRevokeUnsupported;

  /// Cloud provider id of the staff grant, when known.
  final String? provider;

  bool get complete => recorded && keyRetired && keyRingPublished && (tokenRevoked || tokenRevokeUnsupported);

  /// Some step failed and will be retried on the next sync.
  bool get pendingRetry => recorded && !complete;
}

/// Idempotent revocation steps. Each one can be re-run safely.
class StaffRevocation {
  StaffRevocation(this.db);
  final VaultDatabase db;

  static String grantKey(String staffId) => 'staff_grant:$staffId';

  /// Grant record written at pairing / re-pairing: {p, rt, v: 2}. `v: 2` =
  /// minted for the household space; without it, an old owner-app token.
  static String encodeGrant(String provider, String refreshToken) =>
      jsonEncode({'p': provider, 'rt': refreshToken, 'v': 2});

  /// OneDrive revocation can't end one token: set to the provider until the
  /// owner removed the household app's consent and re-issued access.
  static const reissueKey = 'household_reissue_pending';

  Future<String?> reissuePending() => db.meta(reissueKey);

  /// After the owner re-consented the household app: every remaining
  /// active staff grant on [provider] is dead too and is flagged for a
  /// one-scan re-pair (see [needsRegrant]).
  Future<void> markGrantsForReissue(String provider) async {
    final rows = await db.select("SELECT key, value FROM main.vault_meta WHERE key LIKE 'staff_grant:%'");
    for (final r in rows) {
      final k = r['key'], v = r['value'];
      if (k is! String || v is! String) continue;
      try {
        final g = jsonDecode(v) as Map<String, dynamic>;
        if (g['p'] == provider) await db.setMeta(k, jsonEncode({...g, 'reissue': true}));
      } catch (_) {}
    }
    await db.execute('DELETE FROM main.vault_meta WHERE key = ?', [reissueKey], {'vault_meta'});
  }

  /// How this owner device sees [staffId]'s cloud grant.
  Future<GrantState> grantState(String staffId, String? householdProvider) async {
    final raw = await db.meta(grantKey(staffId));
    if (raw == null) return GrantState.missing;
    try {
      final g = jsonDecode(raw) as Map<String, dynamic>;
      if (g['v'] != 2) return GrantState.legacy;
      if (g['reissue'] == true || g['p'] != householdProvider) return GrantState.needsRegrant;
      return GrantState.ok;
    } catch (_) {
      return GrantState.missing;
    }
  }

  /// Retry back-off for a failed token revocation: 1 min, doubling, capped.
  static const _firstRetry = Duration(minutes: 1);
  static const _maxRetry = Duration(hours: 6);

  static int _backoffMs(int attempts) {
    var d = _firstRetry.inMilliseconds;
    for (var i = 1; i < attempts && d < _maxRetry.inMilliseconds; i++) {
      d *= 2;
    }
    return d < _maxRetry.inMilliseconds ? d : _maxRetry.inMilliseconds;
  }

  /// Step 1. Keeps an existing (earlier) `revoked_at`.
  /// Returns `known: false` for an unknown staff id.
  Future<({bool known, bool already})> record(String staffId) async {
    final row = await db.selectOne('SELECT revoked_at FROM staff_members WHERE id = ?', [staffId]);
    if (row == null) return (known: false, already: false);
    if (row['revoked_at'] != null) return (known: true, already: true);
    await db.patch('staff_members', staffId, {'revoked_at': DateTime.now().toUtc().millisecondsSinceEpoch});
    return (known: true, already: false);
  }

  /// Step 2 (channel mode). True when no live channel key remains.
  Future<bool> destroyChannelKey(String staffId) async {
    final keys = StaffChannelKeyStore(db);
    if (await keys.keyFor(staffId) != null) await keys.destroy(staffId);
    return await keys.keyFor(staffId) == null;
  }

  /// Step 4: revoke the delegated cloud grant kept on this owner device.
  /// The grant is forgotten only once the provider confirmed the revoke (or
  /// reported the token already invalid), or when revoking is unsupported.
  /// Failures (offline, 5xx) are retried with exponential back-off stored
  /// as `next_at` in the grant; before that time nothing is attempted or
  /// written. [force] (an explicit user action) ignores the back-off.
  Future<({bool done, bool unsupported, String? provider})> revokeToken(String staffId, {bool force = false}) async {
    final raw = await db.meta(grantKey(staffId));
    if (raw == null) return (done: true, unsupported: false, provider: null);
    Map<String, dynamic> g;
    try {
      g = jsonDecode(raw) as Map<String, dynamic>;
    } catch (_) {
      await _forget(staffId);
      return (done: true, unsupported: false, provider: null);
    }
    final p = g['p'] is String ? g['p'] as String : null;
    final rt = g['rt'] is String ? g['rt'] as String : null;
    if (p == null || rt == null || rt.isEmpty) {
      await _forget(staffId);
      return (done: true, unsupported: false, provider: p);
    }
    // Household grants were minted from the household registration
    // (Google: same client, drive.file grant; Dropbox / OneDrive: the
    // second app) and must be revoked through it.
    final separated = g['v'] == 2;
    final OAuthProviderConfig config;
    try {
      config = separated ? CloudConfig.forHousehold(p) : CloudConfig.forProvider(p);
    } catch (_) {
      await _forget(staffId);
      return (done: false, unsupported: true, provider: p);
    }
    if (config.revokeEndpoint == null) {
      // OneDrive: no per-token revocation. The only cut-off is removing the
      // household app's consent, which ends EVERY household token: remember
      // that the owner still has to do it and re-issue the others.
      if (separated) await db.setMeta(reissueKey, p);
      await _forget(staffId); // nothing we can do with it
      return (done: false, unsupported: true, provider: p);
    }
    final now = DateTime.now().toUtc().millisecondsSinceEpoch;
    final nextAt = g['next_at'] is int ? g['next_at'] as int : 0;
    if (!force && now < nextAt) return (done: false, unsupported: false, provider: p);
    var ok = false;
    try {
      ok = await OAuthSession.revoke(config, rt);
    } on CloudAuthExpired {
      ok = true; // already unusable
    } catch (_) {}
    if (ok) {
      await _forget(staffId);
      return (done: true, unsupported: false, provider: p);
    }
    final n = (g['n'] is int ? g['n'] as int : 0) + 1;
    await db.setMeta(grantKey(staffId), jsonEncode({...g, 'n': n, 'next_at': now + _backoffMs(n)}));
    return (done: false, unsupported: false, provider: p);
  }

  /// Step 3 check: the last key-ring this device uploaded lists [staffId]
  /// as revoked (reads SyncEngine's `sync.pushed:keyring` state).
  Future<bool> keyRingPublished(String staffId) async {
    try {
      final v = await db.meta('sync.pushed:keyring');
      if (v == null) return false;
      final fp = jsonDecode((jsonDecode(v) as Map)['fp'] as String) as Map;
      return (fp['r'] as List).contains(staffId);
    } catch (_) {
      return false;
    }
  }

  /// Every owner sync: finish revocations whose earlier steps failed.
  /// (The key-ring and channel-file clean-up follow from `revoked_at` in
  /// the same sync pass.) Never throws.
  Future<void> resumePending() async {
    if (!db.hasPrivate) return;
    final List<Map<String, Object?>> rows;
    try {
      rows = await db.select('SELECT id FROM staff_members WHERE revoked_at IS NOT NULL');
    } catch (_) {
      return;
    }
    for (final r in rows) {
      final id = r['id'];
      if (id is! String) continue;
      try {
        await destroyChannelKey(id);
      } catch (_) {}
      try {
        await revokeToken(id);
      } on CloudAuthExpired {
        // Staff grant only; never the owner's own session.
      } catch (_) {}
    }
  }

  Future<void> _forget(String staffId) =>
      db.execute('DELETE FROM main.vault_meta WHERE key = ?', [grantKey(staffId)], {'vault_meta'});
}

/// Owner-side view of one staff member's cloud grant.
enum GrantState {
  /// Household-space grant for the current household cloud.
  ok,

  /// Household cloud changed, or OneDrive access was re-issued: one-scan
  /// re-pair code.
  needsRegrant,

  /// Paired before the household space existed (owner-app token): revoke
  /// and pair the phone again.
  legacy,

  /// Not on this owner device (paired on another one).
  missing,
}
