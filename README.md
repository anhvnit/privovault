# PrivoVault — cryptography & sync protocol

PrivoVault is a private vault for net worth, expenses, assets and vehicles, for iOS and Android.
It has **no accounts and no servers that hold user data**: everything is encrypted on the phone and,
if the owner chooses, stored as ciphertext in the owner's own iCloud or Google Drive.

This repository publishes **only the parts that protect that data**, so anyone can review them:
the crypto core, the vault handshake, the encrypted database layer, the native hardware-key bridges,
and the sync / household-sharing protocol. The rest of the app (UI, features, store listings) is not
included. Website: <https://privovault.com> · Privacy policy: <https://privovault.com/privacy/>

## What is here

| Path | What it does |
| --- | --- |
| `packages/privovault_crypto/lib/src/primitives/` | AES-256-GCM (`aead.dart`), HKDF key derivation (`keys.dart`), BIP-39 recovery phrase (`bip39_vendored.dart`, own implementation with the canonical English list), Emergency Kit file sealing with Argon2id + AES-GCM (`encrypted_kit.dart`) |
| `packages/privovault_crypto/lib/src/biometric/` + `android/`, `ios/` | Hardware-bound key release: the master key is wrapped by a Keychain (`.biometryCurrentSet`) / Android Keystore key that the OS only unwraps after a live Face ID / fingerprint match. Two-slot atomic rotation. |
| `packages/privovault_crypto/lib/src/vault/` | Vault handshake: create, unlock, restore from recovery phrase, master-key and identity rotation, household re-key |
| `packages/privovault_crypto/lib/src/db/` | SQLCipher database (owner: `private.db` + attached `shared.db`; staff: `shared.db` only), hardened ATTACH, Hybrid Logical Clock |
| `lib/core/crypto/` | App-side wrappers, staff pairing credentials |
| `lib/core/sync/package_format.dart` | `QLV1` package: header, Ed25519 signature, AES-256-GCM body, size buckets |
| `lib/core/sync/merge_engine.dart` | Per-row last-writer-wins merge, authority rules for staff rows, monotonic revocation |
| `lib/core/sync/keyring.dart`, `signed_marker.dart` | Signed per-owner-device key-rings and markers |
| `lib/core/sync/owner_key_state.dart` | Replicated key state between the owner's own devices; lost-device declaration |
| `lib/core/sync/staff_channel.dart`, `staff_revocation.dart` | Household (staff) channels and revocation |
| `lib/core/sync/sync_engine.dart`, `snapshot.dart` | Sync pass: export, sign, encrypt, upload, verify, merge |
| `lib/core/sync/cloud/cloud_store.dart`, `household_store.dart` | Storage interface, download size caps, and the household store that keeps staff tokens away from the owner's vault folder |
| `docs/ARCHITECTURE.md` | Full design: data split, key hierarchy, sync, pairing, revocation |

## Design in one screen

```
Face ID / fingerprint ──► hardware key (Secure Enclave / Keystore) unwraps
Owner Master Key (32 B random)
  ├─ HKDF → SQLCipher key of private.db      (assets, ledger, net worth — owner only)
  ├─ HKDF → sync key of ql.private.<device>.qlv
  └─ household key K_shared (per epoch, rotatable)
        ├─ HKDF → SQLCipher key of shared.db (household expenses, vehicle logs)
        └─ HKDF → sync key of ql.shared.<device>.qlv
Owner identity: X25519 (pairing, key-rings) + Ed25519 (signatures)
Recovery: 12-word BIP-39 → HKDF → wraps the master key
```

* The cloud provider only ever sees ciphertext (two layers: SQLCipher pages inside an AES-GCM package)
  and coarse, bucketed sizes.
* Staff phones never receive the master key or the private database. Their cloud token reaches only a
  separate household space (Google `drive.file` grant / second app registration), never the owner's
  hidden vault folder.
* Pairing is face to face: two QR scans plus a 6-digit comparison code shown on both phones.
* No analytics, crash reporting, ads or remote config. Market prices are fetched anonymously with the
  owner's symbols mixed into a fixed public basket.

## Threat model (summary)

In scope: a curious or compromised cloud provider; a stolen locked phone; a malicious or revoked staff
member (including a modified app and a stolen staff token); replayed or forged cloud files; a leaked old
Emergency Kit after a new kit is made; a lost owner device.

Out of scope: a fully compromised, unlocked owner phone (malware with OS-level access while the vault is
open); someone who holds the current Emergency Kit; coercion.

Known limitations are written down in `docs/ARCHITECTURE.md` (for example: `drive.file` is per app, so
one staff token could see — but not read or forge — another staff member's encrypted files).

## Running the tests

```bash
cd packages/privovault_crypto
flutter pub get
flutter test
```

The app code that is not published here only calls these APIs; it cannot weaken them.

## Reporting a vulnerability

Please report privately — see [SECURITY.md](SECURITY.md). Do not open a public issue for a security bug.

## Licence

The source is published so it can be read, audited and discussed. No licence to reuse it is granted
yet; all rights reserved. © 2026 PrivoVault.
