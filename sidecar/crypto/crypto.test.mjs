#!/usr/bin/env node
//
// PyxPass crypto unit tests (Milestone 4).
// Run: node --test crypto/crypto.test.mjs  (or npm test)
//
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSalt,
  newIv,
  deriveMasterKey,
  deriveEntryKey,
  deriveEncKey,
  encrypt,
  decrypt,
  encryptEntry,
  decryptEntry,
} from './crypto.mjs';

const PASSWORD = 'correct horse battery staple';
const SALT = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8'); // 32 bytes
const ENTRY_ID = 'entry-1234';
const PLAINTEXT = Buffer.from(
  JSON.stringify({ title: 'Dash testnet seed', username: 'joel', url: 'https://faucet.dash.org' }),
);

test('1. encrypt -> decrypt round-trip recovers plaintext', async () => {
  const { ciphertext, iv } = await encryptEntry(PASSWORD, SALT, ENTRY_ID, 0, PLAINTEXT);
  assert.ok(iv.length === 12, 'iv is 12 bytes');
  assert.ok(ciphertext.length === PLAINTEXT.length + 16, 'ciphertext = plaintext + 16-byte tag');

  const recovered = await decryptEntry(PASSWORD, SALT, ENTRY_ID, 0, ciphertext, iv);
  assert.deepEqual(recovered, PLAINTEXT, 'round-trip must recover identical plaintext');
  assert.equal(recovered.toString('utf8'), PLAINTEXT.toString('utf8'));
});

test('2. wrong password fails to decrypt', async () => {
  const { ciphertext, iv } = await encryptEntry(PASSWORD, SALT, ENTRY_ID, 0, PLAINTEXT);
  // Even one wrong char must fail
  await assert.rejects(
    decryptEntry(`${PASSWORD}x`, SALT, ENTRY_ID, 0, ciphertext, iv),
    /unable to authenticate|authentication|auth tag|decrypt/i,
    'wrong password must throw',
  );
});

test('3. IV uniqueness — two encryptions differ (fresh IV each time)', async () => {
  const a = await encryptEntry(PASSWORD, SALT, ENTRY_ID, 0, PLAINTEXT);
  const b = await encryptEntry(PASSWORD, SALT, ENTRY_ID, 0, PLAINTEXT);
  assert.notDeepEqual(a.iv, b.iv, 'IVs must differ');
  assert.notDeepEqual(a.ciphertext, b.ciphertext, 'ciphertexts must differ (randomized)');
});

test('4. rotation changes encKey (and thus ciphertext)', async () => {
  const masterKey = await deriveMasterKey(PASSWORD, SALT);
  const entryKey = deriveEntryKey(masterKey, ENTRY_ID);
  const encKey0 = deriveEncKey(entryKey, 0, ENTRY_ID);
  const encKey1 = deriveEncKey(entryKey, 1, ENTRY_ID);
  assert.notDeepEqual(encKey0, encKey1, 'encKey must change when rotation bumps');

  // And a doc encrypted at rotation 0 must NOT decrypt at rotation 1
  const { ciphertext, iv } = await encryptEntry(PASSWORD, SALT, ENTRY_ID, 0, PLAINTEXT);
  await assert.rejects(
    decryptEntry(PASSWORD, SALT, ENTRY_ID, 1, ciphertext, iv),
    /unable to authenticate|authentication|auth tag|decrypt/i,
    'rotation 1 must not decrypt a rotation-0 doc',
  );
});

test('5. raw encrypt/decrypt primitives (low-level AES-GCM)', async () => {
  const key = Buffer.alloc(32, 0x11);
  const { ciphertext, iv } = encrypt(PLAINTEXT, key);
  const recovered = decrypt(ciphertext, iv, key);
  assert.deepEqual(recovered, PLAINTEXT);
});

test('6. salt/iv are distinct random values', () => {
  assert.notDeepEqual(generateSalt(), generateSalt(), 'salts differ');
  assert.notDeepEqual(newIv(), newIv(), 'ivs differ');
  assert.equal(generateSalt().length, 16, 'salt is 16 bytes');
  assert.equal(newIv().length, 12, 'iv is 12 bytes');
});
