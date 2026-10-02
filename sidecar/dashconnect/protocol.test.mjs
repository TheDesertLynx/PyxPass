//
// protocol.test.mjs — M9 ACCEPT: wallet-protocol unit tests.
//
// Mirrors the dash wallet suites that define the protocol:
//   - DashConnectUriTests.swift / DashConnectUriTest.kt  -> request bytes
//   - KeyExchangeCryptoTests.swift                      -> crypto vectors
//
// Run: node --test dashconnect/protocol.test.mjs
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveAesKey,
  deriveAuthKeyFromLogin,
  deriveEncryptionKeyFromLogin,
  deriveLoginKey,
  decryptLoginKey,
  encryptLoginKey,
  ecdhSharedX,
  compressedPublicKey,
  hash160,
  toHex,
  fromHex,
} from './crypto.mjs';
import {
  buildKeyExchangeUri,
  parseKeyExchangeUri,
  parseStateTransitionUri,
  buildStateTransitionUri,
  serializeKeyExchangeRequest,
  isKeyUri,
  isStateTransitionUri,
} from './uri.mjs';
import {
  buildLoginKeyResponseDraft,
  buildRegistrationKeyData,
  deriveLoginKeyForContract,
  loginKeyResponseWhereClause,
  validateKeyRegistration,
  YAPPR_KEY_EXCHANGE_CONTRACT_ID,
  LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
  LOGIN_KEY_DERIVATION_KEY_INDEX,
} from './protocol.mjs';
import { base58Decode, base58Encode } from './base58.mjs';

/** Compare byte buffers regardless of Buffer/Uint8Array prototype. */
const eqBytes = (a, b) => assert.deepEqual([...a], [...b]);

// ---- Fixtures matching the kotlin / iOS test vectors ----
const APP_PRIVATE_KEY = Buffer.alloc(32, 0x01); // kotlinAppPrivateKey
const WALLET_PRIVATE_KEY = Buffer.alloc(32, 0x02); // kotlinWalletPrivateKey
const APP_PUBLIC_KEY = compressedPublicKey(APP_PRIVATE_KEY);
const WALLET_PUBLIC_KEY = compressedPublicKey(WALLET_PRIVATE_KEY);
const IDENTITY_ID_BYTES = Buffer.alloc(32, 0xab);
const CONTRACT_ID_BYTES = Buffer.alloc(32, 0xcd);
const IDENTITY_ID_BASE58 = base58Encode(IDENTITY_ID_BYTES);
const CONTRACT_ID_BASE58 = base58Encode(CONTRACT_ID_BYTES);
const KOTLIN_LOGIN_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));

// ---- KeyExchangeCryptoTests.swift vectors ----
const SHARED_X = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const LOGIN_KEY = fromHex('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
const WALLET_EPHEMERAL_PRIV = Buffer.alloc(32, 0x01);
const APP_EPHEMERAL_PUB = fromHex('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f');
const FIXED_NONCE = fromHex('101112131415161718191a1b');

// ============================================================
// hash160
// ============================================================
test('hash160 matches known vector [0x00]*33', () => {
  assert.equal(toHex(hash160(Buffer.alloc(33))), '29cfc6376255a78451eeb4b129ed8eacffa2feef');
});
test('hash160 matches kotlin vector [0x01,0x02,0x03]', () => {
  assert.equal(toHex(hash160(Buffer.from([1, 2, 3]))), '9bc4860bb936abf262d7a51f74b4304833fee3b2');
});

// ============================================================
// AES key derivation (deriveAesKey)
// ============================================================
test('deriveAesKey matches KeyExchangeCryptoTests vector', () => {
  assert.equal(
    toHex(deriveAesKey(SHARED_X)),
    '0d14bc5a19d237e70d82bd357114307629c262c77fcde496d51dfeaa35d124c2',
  );
});

// ============================================================
// ECDH symmetric
// ============================================================
test('ECDH is symmetric: ecdhSharedX(privA, pubB) === ecdhSharedX(privB, pubA)', () => {
  const fromApp = ecdhSharedX(APP_PRIVATE_KEY, WALLET_PUBLIC_KEY);
  const fromWallet = ecdhSharedX(WALLET_PRIVATE_KEY, APP_PUBLIC_KEY);
  assert.deepEqual(fromApp, fromWallet);
  assert.equal(fromApp.length, 32);
});

// ============================================================
// EncryptLoginKey — fixed-nonce payload vector
// ============================================================
test('encryptLoginKey matches the fixed-nonce payload vector byte-for-byte', () => {
  const payload = encryptLoginKey(LOGIN_KEY, WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB, FIXED_NONCE);
  assert.equal(
    toHex(payload),
    '101112131415161718191a1b914189444d0fee69f81c2da90b6e1f451e003d9ef6196f231601d0dbd93c523969bcb8d144051b2b9badadb6e3a80fc8',
  );
});
test('payload has expected length (60) and nonce prefix', () => {
  const payload = encryptLoginKey(LOGIN_KEY, WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB, FIXED_NONCE);
  assert.equal(payload.length, 60);
  assert.deepEqual(payload.subarray(0, 12), FIXED_NONCE);
});
test('encrypt/decrypt round-trips the kotlin login key', () => {
  const appPub = compressedPublicKey(APP_PRIVATE_KEY);
  const payload = encryptLoginKey(KOTLIN_LOGIN_KEY, WALLET_PRIVATE_KEY, appPub, Buffer.alloc(12));
  const decrypted = decryptLoginKey(payload, WALLET_PRIVATE_KEY, appPub);
  assert.deepEqual(decrypted, KOTLIN_LOGIN_KEY);
});
test('rejects invalid payload length', () => {
  assert.throws(() => decryptLoginKey(Buffer.alloc(59), WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB));
});
test('rejects invalid nonce length', () => {
  assert.throws(() => encryptLoginKey(LOGIN_KEY, WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB, Buffer.alloc(11)));
});
test('tampered tag fails to decrypt', () => {
  const payload = encryptLoginKey(LOGIN_KEY, WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB, FIXED_NONCE);
  payload[payload.length - 1] ^= 0x01;
  assert.throws(() => decryptLoginKey(payload, WALLET_EPHEMERAL_PRIV, APP_EPHEMERAL_PUB));
});

// ============================================================
// Derived identity keys (auth / encryption from login key)
// ============================================================
test('deriveAuthKeyFromLogin matches kotlin vector', () => {
  assert.equal(
    toHex(deriveAuthKeyFromLogin(KOTLIN_LOGIN_KEY, IDENTITY_ID_BYTES)),
    'e06ee7ae45f257741dab7379793c854829b67171af111238c664d9fd90603706',
  );
});
test('deriveEncryptionKeyFromLogin matches kotlin vector', () => {
  assert.equal(
    toHex(deriveEncryptionKeyFromLogin(KOTLIN_LOGIN_KEY, IDENTITY_ID_BYTES)),
    '6879c11819d1a60026adae34c296e83d13d06559ad63da41d03c44b203a90f80',
  );
});
test('auth and encryption keys differ', () => {
  const auth = deriveAuthKeyFromLogin(KOTLIN_LOGIN_KEY, IDENTITY_ID_BYTES);
  const enc = deriveEncryptionKeyFromLogin(KOTLIN_LOGIN_KEY, IDENTITY_ID_BYTES);
  assert.notDeepEqual(auth, enc);
});

// ============================================================
// Login-key derivation (wallet side, from chain key)
// ============================================================
test('deriveLoginKey is 32 bytes and deterministic per (identity, contract)', () => {
  const chainKey = Buffer.alloc(32).map((_, i) => i + 1); // 01..20
  const a = deriveLoginKey(chainKey, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const b = deriveLoginKey(chainKey, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
});
test('deriveLoginKey changes with the app contract id', () => {
  const chainKey = Buffer.alloc(32).map((_, i) => i + 1); // 01..20
  const other = Buffer.alloc(32, 0xee);
  const a = deriveLoginKey(chainKey, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const b = deriveLoginKey(chainKey, IDENTITY_ID_BYTES, other);
  assert.notDeepEqual(a, b);
});
test('deriveLoginKey validates input lengths', () => {
  const chainKey = Buffer.alloc(32);
  assert.throws(() => deriveLoginKey(chainKey.subarray(0, 31), IDENTITY_ID_BYTES, CONTRACT_ID_BYTES));
  assert.throws(() => deriveLoginKey(chainKey, IDENTITY_ID_BYTES.subarray(0, 31), CONTRACT_ID_BYTES));
  assert.throws(() => deriveLoginKey(chainKey, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES.subarray(0, 31)));
});

// ============================================================
// Serialized request — DashConnectUriTest.kt fixture
// ============================================================
const SERIALIZED_REQUEST_HEX =
  '01031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f' +
  'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
  '0e4c6f67696e20746f205961707072';

test('serializeKeyExchangeRequest is byte-identical to the kotlin fixture', () => {
  const bytes = serializeKeyExchangeRequest({
    appEphemeralPubKey: APP_EPHEMERAL_PUB,
    contractId: CONTRACT_ID_BYTES,
    label: 'Login to Yappr',
  });
  assert.equal(toHex(bytes), SERIALIZED_REQUEST_HEX);
});

// ============================================================
// dash-key: URI build + parse round-trip
// ============================================================
test('buildKeyExchangeUri produces a valid dash-key: URI', () => {
  const uri = buildKeyExchangeUri({
    appEphemeralPubKey: APP_EPHEMERAL_PUB,
    contractId: CONTRACT_ID_BYTES,
    label: 'Login to Yappr',
  }, 'testnet');
  assert.ok(uri.startsWith('dash-key:'));
  assert.ok(uri.endsWith('?n=t&v=1'));
});
test('dash-key: URI parses back to the original request (testnet)', () => {
  const uri = buildKeyExchangeUri({
    appEphemeralPubKey: APP_EPHEMERAL_PUB,
    contractId: CONTRACT_ID_BYTES,
    label: 'Login to Yappr',
  }, 'testnet');
  const parsed = parseKeyExchangeUri(uri);
  assert.ok(parsed);
  assert.equal(parsed.network, 'testnet');
  assert.equal(parsed.version, 1);
  eqBytes(parsed.request.appEphemeralPubKey, APP_EPHEMERAL_PUB);
  eqBytes(parsed.request.contractId, CONTRACT_ID_BYTES);
  assert.equal(parsed.request.label, 'Login to Yappr');
});
test('dash-key: URI supports all networks', () => {
  for (const [network, id] of [['mainnet', 'm'], ['testnet', 't'], ['devnet', 'd']]) {
    const uri = buildKeyExchangeUri({ appEphemeralPubKey: APP_EPHEMERAL_PUB, contractId: CONTRACT_ID_BYTES }, network);
    assert.equal(parseKeyExchangeUri(uri).network, network);
  }
});
test('parseKeyExchangeUri rejects malformed URIs', () => {
  assert.equal(parseKeyExchangeUri('dash:123?n=t&v=1'), null); // wrong scheme
  assert.equal(parseKeyExchangeUri('dash-key:abc'), null); // missing query
  assert.equal(parseKeyExchangeUri('dash-key:?n=t&v=1'), null); // empty body
  assert.equal(parseKeyExchangeUri('dash-key://abc?n=t&v=1'), null); // authority
});

// ============================================================
// dash-st: URI build + parse
// ============================================================
test('dash-st: URI round-trips transition bytes', () => {
  const bytes = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  const uri = buildStateTransitionUri(bytes, 'testnet');
  const parsed = parseStateTransitionUri(uri);
  assert.ok(parsed);
  eqBytes(parsed.transitionBytes, bytes);
  assert.equal(parsed.network, 'testnet');
  assert.equal(parsed.version, 1);
});
test('isKeyUri / isStateTransitionUri distinguish kinds', () => {
  const key = buildKeyExchangeUri({ appEphemeralPubKey: APP_EPHEMERAL_PUB, contractId: CONTRACT_ID_BYTES });
  const st = buildStateTransitionUri(Buffer.from([1, 2]));
  assert.ok(isKeyUri(key));
  assert.ok(!isKeyUri(st));
  assert.ok(isStateTransitionUri(st));
  assert.ok(!isStateTransitionUri(key));
});

// ============================================================
// loginKeyResponse draft — wallet side
// ============================================================
test('buildLoginKeyResponseDraft produces the wallet-shaped response doc', () => {
  const draft = buildLoginKeyResponseDraft({
    loginKey: KOTLIN_LOGIN_KEY,
    appContractId: CONTRACT_ID_BYTES,
    appEphemeralPubKey: APP_EPHEMERAL_PUB,
    walletEphemeralPrivateKey: WALLET_PRIVATE_KEY,
  });
  const props = draft.properties;
  assert.equal(props.contractId, CONTRACT_ID_BASE58);
  assert.equal(props.appEphemeralPubKeyHash, toHex(hash160(APP_EPHEMERAL_PUB)));
  assert.equal(props.walletEphemeralPubKey, toHex(compressedPublicKey(WALLET_PRIVATE_KEY)));
  assert.equal(props.encryptedPayload.length, 120); // 60 bytes hex
  assert.equal(props.keyIndex, LOGIN_KEY_DERIVATION_KEY_INDEX);
  assert.equal(draft.walletEphemeralPublicKey.length, 33);
  assert.equal(draft.encryptedPayload.length, 60);
});
test('buildLoginKeyResponseDraft encrypts a decryptable login key (round-trip)', () => {
  const draft = buildLoginKeyResponseDraft({
    loginKey: KOTLIN_LOGIN_KEY,
    appContractId: CONTRACT_ID_BYTES,
    appEphemeralPubKey: APP_EPHEMERAL_PUB,
    walletEphemeralPrivateKey: WALLET_PRIVATE_KEY,
  });
  // The app decrypts with (appEphemeralPriv, walletEphemeralPub):
  const decrypted = decryptLoginKey(draft.encryptedPayload, APP_PRIVATE_KEY, draft.walletEphemeralPublicKey);
  assert.deepEqual(decrypted, KOTLIN_LOGIN_KEY);
});

// ============================================================
// Key registration validation (first-login detection)
// ============================================================
test('validateKeyRegistration reports registered keys present', () => {
  const loginKey = deriveLoginKeyForContract(WALLET_PRIVATE_KEY, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const authPriv = deriveAuthKeyFromLogin(loginKey, IDENTITY_ID_BYTES);
  const encPriv = deriveEncryptionKeyFromLogin(loginKey, IDENTITY_ID_BYTES);
  const authPub = compressedPublicKey(authPriv);
  const encPub = compressedPublicKey(encPriv);

  const identityPublicKeys = [
    { id: 0, type: 0, publicKey: toHex(hash160(authPub)), securityLevel: 0 }, // MASTER ECDSA_HASH160
    { id: 2, type: 0, publicKey: toHex(hash160(authPub)), securityLevel: 1 }, // auth HIGH
    { id: 4, type: 4, publicKey: toHex(encPub), securityLevel: 2 }, // enc MEDIUM ECDSA_SECP256K1
  ];
  const result = validateKeyRegistration({ loginKey, identityIdBytes: IDENTITY_ID_BYTES, identityPublicKeys });
  assert.equal(result.registered, true);
  assert.equal(result.authenticationPresent, true);
  assert.equal(result.encryptionPresent, true);
});
test('validateKeyRegistration reports missing keys when unregistered', () => {
  const loginKey = deriveLoginKeyForContract(WALLET_PRIVATE_KEY, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const result = validateKeyRegistration({ loginKey, identityIdBytes: IDENTITY_ID_BYTES, identityPublicKeys: [] });
  assert.equal(result.registered, false);
  assert.equal(result.authenticationPresent, false);
  assert.equal(result.encryptionPresent, false);
});

// ============================================================
// Base58 codec — real identifiers
// ============================================================
test('base58 round-trips real Dash identifiers', () => {
  const ids = [
    '7UaqHGBJBbRLJ4fUWS45cnud8PPUugJWoGTt1SKwHJ2P', // yappr key-exchange contract
    '5dNzK6FTWkBXyvwRvG2awxcbi3LmJaHCyGiyas7MXJtf', // identity id
    '2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL', // PyxPass contract
  ];
  for (const id of ids) {
    const decoded = base58Decode(id);
    assert.equal(decoded.length, 32, `${id} should be 32 bytes`);
    assert.equal(base58Encode(decoded), id);
  }
});

// ============================================================
// Registration key material (first-login, dash-st:)
// ============================================================
test('buildRegistrationKeyData produces auth hash160 + enc pub key', () => {
  const loginKey = deriveLoginKeyForContract(WALLET_PRIVATE_KEY, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const data = buildRegistrationKeyData(loginKey, IDENTITY_ID_BYTES);

  // auth: ECDSA_HASH160 stores hash160 of the auth pub key
  const authPubHash = hash160(data.authPublicKey);
  eqBytes(data.authKeyData, authPubHash);
  assert.equal(data.authKeyData.length, 20);

  // enc: ECDSA_SECP256K1 stores the enc pub key directly (33 bytes)
  eqBytes(data.encKeyData, data.encPublicKey);
  assert.equal(data.encKeyData.length, 33);

  // auth pub is compressed (33 bytes), starts with 0x02/0x03
  assert.equal(data.authPublicKey.length, 33);
  assert.equal(data.encPublicKey.length, 33);
});
test('buildRegistrationKeyData keys match what validateKeyRegistration recognizes', () => {
  const loginKey = deriveLoginKeyForContract(WALLET_PRIVATE_KEY, IDENTITY_ID_BYTES, CONTRACT_ID_BYTES);
  const data = buildRegistrationKeyData(loginKey, IDENTITY_ID_BYTES);

  const identityPublicKeys = [
    { id: 5, type: 0, publicKey: toHex(data.authKeyData), securityLevel: 1 }, // auth HIGH ECDSA_HASH160
    { id: 6, type: 4, publicKey: toHex(data.encKeyData), securityLevel: 2 }, // enc MEDIUM ECDSA_SECP256K1
  ];
  const result = validateKeyRegistration({ loginKey, identityIdBytes: IDENTITY_ID_BYTES, identityPublicKeys });
  assert.equal(result.registered, true);
});

// ============================================================
// Protocol constants
// ============================================================
test('protocol constants are pinned correctly', () => {
  assert.equal(YAPPR_KEY_EXCHANGE_CONTRACT_ID, '7UaqHGBJBbRLJ4fUWS45cnud8PPUugJWoGTt1SKwHJ2P');
  assert.equal(LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE, 'loginKeyResponse');
  assert.equal(LOGIN_KEY_DERIVATION_KEY_INDEX, 0);
});
test('loginKeyResponseWhereClause targets owner + app contract', () => {
  const clause = loginKeyResponseWhereClause(IDENTITY_ID_BASE58, CONTRACT_ID_BYTES);
  assert.deepEqual(clause, [
    ['$ownerId', '==', IDENTITY_ID_BASE58],
    ['contractId', '==', CONTRACT_ID_BASE58],
  ]);
});
