# PrivoVault — Architecture

Flutter (Dart 3) · SQLCipher via `sqflite_sqlcipher` · biometrics via `local_auth` + hardware-bound key release · BYOC sync (iCloud container, Google Drive `drive.appdata`; OneDrive / Dropbox app folders implemented but currently disabled) · on-device AI and OCR only · zero telemetry · English, Vietnamese, Arabic (RTL), Norwegian, French.

## 0. Repository layout (monorepo)

```
/                         PrivoVault app (UI, features, sync, l10n)
packages/privovault_crypto  standalone crypto core: biometric key release (plugin, iOS + Android)
                            + SQLCipher initialisation (VaultHandshake, VaultDatabase). No UI.
website/                  privovault.com (static, 5 languages)
```

The app injects its schema (`lib/core/db/privovault_schema.dart`), localised prompts and seed data;
`lib/core/db/vault_database_service.dart` adapts package sessions to the app's `UnlockedVault`.
Old import paths (`core/crypto/*`, `core/db/vault_database.dart`, `core/util/hlc.dart`) re-export the package.

## 1. Data split: two encrypted files

| File | Who holds the key | Contents |
|---|---|---|
| `private.db` | **Owner devices only** (key derived from Owner Master Key) | accounts & balances, owner ledger, assets, lots, valuations, liabilities, net-worth snapshots, passive income, vehicle purchase price & depreciation, owner chat, staff OAuth grants, household key history |
| `shared.db` | Owner **and** paired staff (household key `K_shared`, rotatable by epoch) | categories, vehicles (ops only), ODO / fuel / service / compliance / reminders, mileage trips, `household_expenses`, `household_chat`, `staff_members` |

Owner devices open `private.db` as `main` and `ATTACH shared.db AS shared KEY …`. SQLite resolves unqualified table names across both, so feature code never needs to know the split. Staff devices open only `shared.db`; private tables don't exist in their connection at all. Schemas live in `assets/sql/` and migrations in `VaultDatabase` (`lib/core/db/vault_database.dart`).

## 2. Key hierarchy

```
FaceID / BiometricPrompt
   │  KeyRelease (lib/core/crypto/key_release.dart)
   │   • HardwareBoundKeyRelease (default): Keychain .biometryCurrentSet /
   │     Keystore AES-GCM wrap key + BiometricPrompt CryptoObject (TEE/StrongBox)
   │   • LocalAuthKeyRelease: local_auth prompt + flutter_secure_storage (weaker)
   ▼
Owner Master Key (32 B random, wiped after derivation)
   ├─HKDF→ K_private.sqlcipher  → private.db
   ├─HKDF→ K_behavior           → behavior_profile.json (AES-256-GCM)
   ├─HKDF→ K_private.sync       → ql.private.<device>.qlv
   └─ private.db › household_key_e<n> (K_shared root, per epoch)
          ├─HKDF→ K_shared.sqlcipher → shared.db
          └─HKDF→ K_shared.sync      → ql.shared.<device>.qlv
Owner identity: X25519 (key-ring/invites) + Ed25519 (package & key-ring signatures)
Recovery: 12-word BIP-39 (vendored implementation, Trezor test vectors) → HKDF → wraps MK;
  wrapped MK rides in every private package header
New Emergency Kit: rotates MK **and** the owner X25519/Ed25519 identity, re-encrypts, then
  permanently deletes the old packages (where the provider supports it); staff must re-pair
Emergency Kit: printed = words in clear (paper lives off the phone);
  saved as file = words sealed with a kit password (Argon2id 32 MiB/t=3 + AES-256-GCM),
  never plaintext on the device — a lost phone's Files app reveals nothing
```

Why not `local_auth` alone: it returns a boolean in app code. On a jailbroken/rooted device or a patched binary that check can be skipped and the key read straight from storage. With the hardware-bound strategy the OS refuses to release the key unless the biometric sensor just matched — there is no boolean to patch. `local_auth` is still used for capability detection and step-up confirmation (Emergency Kit, Add/Revoke staff). Switch strategies in `keyReleaseProvider`.

## 3. Sync (BYOC)

* **Providers**: iCloud (app container) and Google Drive (`drive.appdata`, the hidden per-app folder). OneDrive (`Files.ReadWrite.AppFolder`) and Dropbox (App folder) stores exist but are switched off (`kOfferOneDriveDropbox`). Factory: `lib/core/sync/cloud/cloud_store_factory.dart`.
* **Single-writer files**: each device writes only its own `ql.<scope>.<deviceId>.qlv`; everyone reads everyone else's. No two devices ever overwrite the same cloud file.
* **Package** = `QLV1 | header | Ed25519 signature | AES-256-GCM(body)`; body = SQLCipher snapshot (`sqlcipher_export`) + sealed behavior profile, padded to 64 KiB buckets. Two encryption layers; the provider sees ciphertext and coarse size only. Downloads are size-capped (packages 64 MiB, key-rings 1 MiB, markers 64 KiB) and checked before and after transfer.
* **Merge**: per-row last-writer-wins on a Hybrid Logical Clock (deterministic, idempotent, order-independent); future-dated HLCs are rejected. Rows edited on both sides since the last merge are recorded (locally, encrypted) in `sync_conflicts`.
* **Authority**: packages are verified against the signer's Ed25519 key; revoked or declared-lost signers are refused. From staff peers only rows they authored, in staff-writable tables, within their category/amount/currency limits, are accepted. Revocation is monotonic: a later write can never un-revoke a staff member.
* **Owner key state across owner devices**: household epochs and keys, staff grants and channel mode live in the replicated private table `owner_key_state` (inside the owner's private package, under the master key). Highest epoch wins; equal epochs tie-break on the lowest key fingerprint; no generation is ever dropped (`lib/core/sync/owner_key_state.dart`).
* **Lost owner device**: an owner can declare a device lost (biometric step-up); every owner device then refuses and deletes that device's packages and key-ring, and a new Emergency Kit can be made without it.
* **Restore** tries every candidate package (newest header first); a signature or MAC failure on one never blocks the others.
* Sync runs only while the vault is unlocked. There is no OS background sync by design: nothing can be decrypted without the biometric-released key.

## 4. Owner & Staff mode

* **Household space, separate from the owner's vault**: staff channels never live in the owner's vault folder.
  * Google Drive: a visible `PrivoVault Household/<staffId>/` folder created by the app. Staff tokens come from a **separate OAuth grant requesting only `drive.file`**, so they cannot read the hidden `drive.appdata` folder that holds the owner's packages.
  * OneDrive / Dropbox (when enabled): a **second app registration** ("PrivoVault Household") with its own app folder; staff tokens are minted from that app only.
  * iCloud: the household uses one of the above (an iCloud container belongs to one Apple ID).
  * A staff store can only reach its own sub-folder, plus exact-name reads and `ql.keyring.*` listing in the household root; it can never write the root (`lib/core/sync/cloud/household_store.dart`).
  * Known limit: `drive.file` is per app, so one staff token could in principle see another staff member's sub-folder. Contents are encrypted and signed per staff member; deletion is a denial of service the owner detects and repairs.
* **Pairing (face to face, no server, no email)**:
  1. Staff phone shows **QR-A**: its X25519 + Ed25519 public keys and a fresh nonce.
  2. Owner scans, the owner generates the staff id, sets permissions, and shows **QR-B1** (public values only).
  3. Both phones display the same **6-digit code** = SHA-256 over both phones' public keys, both nonces, the staff id and the invite id. The owner confirms "codes match".
  4. Owner shows **QR-B2** = AES-GCM(ECDH(owner, staff), {K_shared, owner public keys, household-only cloud grant, permissions, expiry}); the staff phone checks it matches B1 and the code. Replayed nonces, staff keys and invite ids are refused.
* **Enforcement**: cryptographic (no private key on staff devices) + UI (`RoleShell` never builds Wealth/Vault tabs for staff).
* **Key-rings**: each owner device writes its own signed `ql.keyring.<ownerDeviceId>.qlk`; staff take the newest valid one (highest epoch, then HLC) from a non-lost owner device. After an owner identity rotation, every ring carries a notice signed with the replaced key, so staff phones can tell "owner rotated keys, pair again" from forgery.
* **Revocation**: mark revoked (monotonic) → revoke the cloud grant (Google/Dropbox per token; OneDrive cannot revoke a single refresh token, so the owner removes the household app's consent and re-issues access to remaining staff) → new household epoch → re-key of shared.db → new signed key-rings give the new key to remaining staff only → the revoked device wipes itself on its next sync.

## 5. On-device AI

See `docs/modules/CHAT.md`. Speech: iOS `SFSpeechRecognizer(requiresOnDeviceRecognition)`, Android `createOnDeviceSpeechRecognizer`. Parsing: deterministic VN/EN rule parser first, then Apple Foundation Models (iOS 26+) / Gemini Nano via ML Kit GenAI Prompt API / ML Kit Entity Extraction. Every parse becomes a Draft Card; nothing is written until **Confirm & Vault**.

## 6. Privacy of market data

Prices come from keyless public endpoints with no cookies or identifiers. User symbols are mixed into a fixed public basket and shuffled. Quantities and values never leave the device. See `docs/modules/WEALTH.md`.

## 7. Telemetry

None. No Firebase, Crashlytics, analytics or remote config. Fonts are bundled, not fetched.
