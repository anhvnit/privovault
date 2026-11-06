# Security policy

We welcome review of everything in this repository: the crypto core, the vault handshake, the
encrypted database layer, the native hardware-key bridges and the sync / household protocol.

## How to report

* **Preferred:** GitHub → this repository → **Security** → **Report a vulnerability**
  (private advisory, visible only to the maintainers).
* **Email:** privacy@privovault.com — subject starting with `[security]`.

Please include the file and line, what an attacker needs (position, access, prior knowledge), what they
gain, and a proof of concept if you have one. Do not include anyone's real data.

## What to expect

* Acknowledgement within 3 working days.
* An assessment and planned fix within 14 days for confirmed issues.
* Credit in the release notes if you would like it.
* Please give us a reasonable time to ship a fix before publishing details (90 days by default).

## In scope

Key handling and derivation, AES-GCM / SQLCipher usage, the `QLV1` package format and signatures,
merge authority rules, key-rings, pairing (QR + comparison code), revocation, restore, master-key and
identity rotation, lost-device handling, and isolation of staff cloud tokens from the owner's data.

## Out of scope

Issues that need a fully compromised and unlocked owner phone, possession of the current Emergency Kit,
or physical coercion; denial of service by a party that already controls the owner's cloud account;
missing hardening of the parts of the app that are not published here (report those by email anyway).
