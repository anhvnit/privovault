import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:privovault_crypto/privovault_crypto.dart';

Uint8List bytes(int n, [int seed = 7]) => Uint8List.fromList(List.generate(n, (i) => (i * 31 + seed) & 0xff));

void main() {
  group('HLC', () {
    test('string order equals causal order, even if the wall clock goes back', () {
      var t = 1000;
      final c = HlcClock('nodeA', wallClock: () => t);
      final a = c.now();
      final b = c.now();
      t = 999;
      final d = c.now();
      expect(a.compareTo(b) < 0, isTrue);
      expect(b.compareTo(d) < 0, isTrue);
    });

    test('observe moves past a remote timestamp', () {
      final c = HlcClock('a', wallClock: () => 10);
      c.observe(HlcClock.encode(50, 3, 'b'));
      expect(c.now().compareTo(HlcClock.encode(50, 3, 'b')) > 0, isTrue);
    });

    test('node id starts at SQL substr(hlc, 22)', () {
      expect(HlcClock.encode(1793855520856, 5, 'dev-123').substring(21), 'dev-123');
    });
  });

  group('SQLCipher helpers', () {
    test('raw key literal skips PBKDF2 (x\'<64 hex>\')', () {
      final lit = rawKeyLiteral(Uint8List(32)..[0] = 0xab);
      expect(lit.length, 67);
      expect(lit.startsWith("x'ab"), isTrue);
      expect(() => rawKeyLiteral(Uint8List(16)), throwsArgumentError);
    });

    test('splitSqlScript strips comments containing semicolons', () {
      final s = splitSqlScript("CREATE TABLE a (x INT); -- FREQ=MONTHLY;BYMONTHDAY=5\nCREATE TABLE b (y INT);\n");
      expect(s, ['CREATE TABLE a (x INT)', 'CREATE TABLE b (y INT)']);
    });
  });

  group('VaultSchema', () {
    final schema = VaultSchema(
      sharedMigrations: [() async => 'CREATE TABLE s (id TEXT PRIMARY KEY, hlc TEXT NOT NULL, deleted_at INTEGER)'],
      privateMigrations: [() async => '', () async => ''],
      sharedTables: const ['s'],
      privateTables: const ['p', 'snap'],
      primaryKeys: const {'snap': 'day'},
      extraTables: const {'cache'},
    );

    test('versions follow migration count', () {
      expect(schema.sharedVersion, 1);
      expect(schema.privateVersion, 2);
    });

    test('scopes, primary keys, watch set', () {
      expect(schema.tablesOf(DataScope.private), ['p', 'snap']);
      expect(schema.pkOf('snap'), 'day');
      expect(schema.pkOf('p'), 'id');
      expect(schema.allTables, containsAll(['s', 'p', 'snap', 'cache', 'vault_meta']));
    });
  });

  group('AEAD & key derivation', () {
    test('seal/open round trip; AAD is bound', () async {
      final k = bytes(32);
      final sealed = await Aead.seal(k, utf8.encode('secret'), aad: utf8.encode('ctx'));
      expect(utf8.decode(await Aead.open(k, sealed, aad: utf8.encode('ctx'))), 'secret');
      expect(() => Aead.open(k, sealed, aad: utf8.encode('other')), throwsA(isA<SecretBoxAuthenticationError>()));
    });

    test('purpose keys are distinct and deterministic', () async {
      final a = await VaultKeys.derive(bytes(32), 'vault-1');
      final b = await VaultKeys.derive(bytes(32), 'vault-1');
      final c = await VaultKeys.derive(bytes(32), 'vault-2');
      expect(a.sqlcipher, b.sqlcipher);
      expect(a.sqlcipher, isNot(c.sqlcipher)); // salted by vault id
      expect(a.sqlcipher, isNot(a.sync));
      expect(a.sync, isNot(a.behavior));
    });

    test('household keys differ per epoch', () async {
      final e1 = await SharedKeys.derive(bytes(32), 'v', 1);
      final e2 = await SharedKeys.derive(bytes(32, 8), 'v', 2);
      expect(e1.sqlcipher, isNot(e2.sqlcipher));
      expect(e1.sync, isNot(e1.sqlcipher));
    });

    test('wipe zeroes key material', () async {
      final k = await VaultKeys.derive(bytes(32), 'v');
      k.wipeAll();
      expect(k.sqlcipher.every((b) => b == 0), isTrue);
    });
  });

  group('Recovery phrase', () {
    test('12 words wrap/unwrap; wrong phrase or vault fails', () async {
      final mk = bytes(32, 3);
      final phrase = RecoveryPhrase.generate();
      expect(phrase.split(' ').length, 12);
      expect(RecoveryPhrase.isValid(phrase), isTrue);
      final wrapped = await RecoveryPhrase.wrapMasterKey(mk, phrase, 'v1');
      expect(await RecoveryPhrase.unwrapMasterKey(wrapped, '  ${phrase.toUpperCase()} ', 'v1'), mk);
      expect(() => RecoveryPhrase.unwrapMasterKey(wrapped, RecoveryPhrase.generate(), 'v1'), throwsA(anything));
      expect(() => RecoveryPhrase.unwrapMasterKey(wrapped, phrase, 'v2'), throwsA(anything));
    });
  });

  group('Encrypted recovery kit (file form)', () {
    test('round trip; no words in the payload; wrong password fails', () async {
      final phrase = RecoveryPhrase.generate();
      final kit = await EncryptedRecoveryKit.seal(phrase: phrase, vaultId: 'vault-9', password: 'correct horse battery');
      expect(EncryptedRecoveryKit.looksLikeKit(kit), isTrue);
      for (final w in phrase.split(' ')) {
        expect(kit.contains(w), isFalse); // ciphertext only
      }
      final r = await EncryptedRecoveryKit.open(kit, 'correct horse battery');
      expect(r.phrase, phrase);
      expect(r.vaultId, 'vault-9');
      await expectLater(EncryptedRecoveryKit.open(kit, 'wrong password!!'), throwsA(isA<SecretBoxAuthenticationError>()));
    });

    test('rejects short passwords and foreign input', () async {
      expect(() => EncryptedRecoveryKit.seal(phrase: RecoveryPhrase.generate(), vaultId: 'v', password: 'short'),
          throwsArgumentError);
      await expectLater(EncryptedRecoveryKit.open('qlv-recovery:1:abc', 'x' * 12), throwsFormatException);
    });
  });

  test('wipe zeroes owned buffers and tolerates read-only ones', () {
    final owned = Uint8List.fromList([1, 2, 3]);
    wipe(owned);
    expect(owned, [0, 0, 0]);
    final readOnly = Uint8List.fromList([9, 9]).asUnmodifiableView();
    expect(() => wipe(readOnly), returnsNormally); // platform-channel buffers
  });

  test('UnlockPrompts.english has every prompt', () {
    const p = UnlockPrompts.english;
    for (final s in [p.createVault, p.unlockOwner, p.unlockStaff, p.secureDevice, p.applyKeyUpdate, p.protectRestored]) {
      expect(s, isNotEmpty);
    }
  });
}
