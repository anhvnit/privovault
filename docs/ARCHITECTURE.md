# PrivoVault — Architecture

Flutter (Dart 3) · SQLCipher via `sqflite_sqlcipher` · biometrics via `local_auth` + hardware-bound key release · BYOC sync (Google Drive `drive.appdata`, OneDrive App Folder, Dropbox App folder) · on-device AI and OCR only · zero telemetry · English, Vietnamese, Arabic (RTL), Norwegian, French.

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
Recovery: 12-word BIP-39 → HKDF → wraps MK; wrapped MK rides in every private package header
Emergency Kit: printed = words in clear (paper lives off the phone);
  saved as file = words sealed with a kit password (Argon2id 32 MiB/t=3 + AES-256-GCM),
  never plaintext on the device — a lost phone's Files app reveals nothing
```

Why not `local_auth` alone: it returns a boolean in app code. On a jailbroken/rooted device or a patched binary that check can be skipped and the key read straight from storage. With the hardware-bound strategy the OS refuses to release the key unless the biometric sensor just matched — there is no boolean to patch. `local_auth` is still used for capability detection and step-up confirmation (Emergency Kit, Add/Revoke staff). Switch strategies in `keyReleaseProvider`.

## 3. Sync (BYOC)

* **Providers**: Google Drive (`drive.appdata`), OneDrive (`Files.ReadWrite.AppFolder`), Dropbox (App folder, `files.*` scopes) — `cloudStoreFor()` in `lib/core/sync/cloud/cloud_store_factory.dart`.
* **Single-writer files**: each device writes only `ql.<scope>.<deviceId>.qlv`; everyone reads everyone else's. No two devices ever overwrite the same cloud file.
* **Package** = `QLV1 | header | Ed25519 signature | AES-256-GCM(body)`; body = SQLCipher snapshot (`sqlcipher_export`) + sealed behavior profile, padded to 64 KiB buckets. Two encryption layers; the provider sees ciphertext and coarse size only.
* **Change detection**: provider content hash (Drive `md5Checksum`, OneDrive `cTag`) vs. last merged → skip unchanged; local max HLC vs. last pushed → skip clean.
* **Merge**: per-row last-writer-wins on Hybrid Logical Clock (deterministic, idempotent, order-independent). Rows edited on both sides since the last merge are recorded (locally, encrypted) in `sync_conflicts` → *Edits to review* screen.
* **Authority**: packages are verified against the signer's Ed25519 key. From staff peers only rows they authored, in staff-writable tables, are accepted.
* Sync runs while the vault is unlocked (on unlock, resume, 20 s after writes, every 15 min). There is no OS background sync by design: nothing can be decrypted without the biometric-released key.

## 4. Owner & Staff mode

* **Pairing (two scans, no server, no email)**: staff phone shows QR-A (its X25519 + Ed25519 public keys) → owner scans, sets role/permissions, approves a separate app-folder-only OAuth grant → owner shows QR-B = AES-GCM(ECDH(owner, staff), {K_shared, owner public keys, cloud grant, permissions, 5-min expiry}). A photographed QR-B is useless without that staff phone's private key.
* **Permissions**: the owner edits each staff member's allowed categories, vehicles and limits; staff phones read them live from the synced `staff_members` row (no re-pairing).
* **Enforcement**: cryptographic (no private key on staff devices) + UI (`RoleShell` never builds Wealth/Vault tabs for staff; `ledgerProvider` throws `OwnerOnlyAccess`).
* **Revocation**: mark revoked → revoke the Google grant → new household epoch → `sqlcipher_export` re-key of shared.db → signed key-ring (`ql.keyring.qlk`) gives the new key to the remaining staff only → revoked device wipes itself on its next sync, and its file is deleted.
* **Cloud-access caveat**: a Google/Microsoft app folder belongs to one account, so a staff device uses a delegated grant to the owner's app folder. It can't decrypt `private`, but it *can* delete files there. Owner devices keep local copies and re-upload missing or altered files on every sync.

## 5. On-device AI

See `docs/modules/CHAT.md`. Speech: iOS `SFSpeechRecognizer(requiresOnDeviceRecognition)`, Android `createOnDeviceSpeechRecognizer`. Parsing: deterministic VN/EN rule parser first, then Apple Foundation Models (iOS 26+) / Gemini Nano via ML Kit GenAI Prompt API / ML Kit Entity Extraction. Every parse becomes a Draft Card; nothing is written until **Confirm & Vault**.

## 6. Privacy of market data

Prices come from keyless public endpoints with no cookies or identifiers. User symbols are mixed into a fixed public basket and shuffled. Quantities and values never leave the device. See `docs/modules/WEALTH.md`.

## 7. Telemetry

None. No Firebase, Crashlytics, analytics or remote config. Fonts are bundled, not fetched.
