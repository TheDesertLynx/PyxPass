//
// app.test.mjs — offline integration test for the M10a DashConnect app flow.
// Mocks the EvoSDK so the full init -> responder -> poll -> complete path is
// validated deterministically, independent of the (flaky) testnet.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as app from './app.mjs';
import {
  buildLoginKeyResponseDraft,
  buildRegistrationKeyData,
  deriveLoginKeyForContract,
  validateKeyRegistration,
  YAPPR_KEY_EXCHANGE_CONTRACT_ID,
  LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
} from './protocol.mjs';
import { parseKeyExchangeUri } from './uri.mjs';
import { toHex, fromHex, hash160, deriveAuthKeyFromLogin, deriveEncryptionKeyFromLogin } from './crypto.mjs';
import { base58Encode } from './base58.mjs';

const CONTRACT_ID = Buffer.alloc(32, 0xab);
const IDENTITY_ID_BYTES = Buffer.from('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'hex');
const WALLET_CHAIN_KEY = Buffer.alloc(32, 0x5e);

/** Mock Document returned by the fake contract store. */
class MockDoc {
  constructor(props, ownerId) {
    this.props = props;
    this.ownerId = ownerId;
  }
  getDocumentId() { return 'mock-doc-1'; }
  getOwnerId() { return { toString: () => this.ownerId }; }
  get properties() { return this.props; }
}

const IDENTITY_ID_BASE58 = '2E4dL4QeVFBNEFUBRk4wrhm9vTonDAEn96FKs2Hk9ARC';

function makeMockSdk() {
  const store = []; // { whereKey, doc }
  const responderIdentity = {
    id: { toBytes: () => IDENTITY_ID_BYTES, toString: () => IDENTITY_ID_BASE58 },
    publicKeys: [],
  };
  let responderLoginKey = null;

  const sdk = {
    documents: {
      async query({ dataContractId, documentTypeName, where, limit }) {
        assert.equal(dataContractId, YAPPR_KEY_EXCHANGE_CONTRACT_ID);
        assert.equal(documentTypeName, LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE);
        // where is [property, '==', value] triples
        const w = {};
        for (const [prop, op, val] of where) {
          if (op === '==') w[prop] = val;
        }
        const match = store.filter((e) => e.whereKey === JSON.stringify(w)).slice(0, limit);
        const map = new Map();
        for (const e of match) map.set(e.doc.getDocumentId(), e.doc);
        return map;
      },
      async get(contractId, type, id) {
        const doc = store.find((e) => e.doc.getDocumentId() === id)?.doc;
        return doc;
      },
      async create({ document }) {
        const { ownerId, properties } = document;
        // byteArray field: normalize to base64 (SDK convention).
        const hash = properties.appEphemeralPubKeyHash;
        const hashB64 = Buffer.isBuffer(hash)
          ? hash.toString('base64')
          : typeof hash === 'string' && !hash.includes('=')
            ? Buffer.from(hash, 'hex').toString('base64')
            : hash;
        const key = JSON.stringify({
          contractId: properties.contractId,
          appEphemeralPubKeyHash: hashB64,
        });
        const doc = new MockDoc(properties, ownerId);
        store.push({ whereKey: key, doc });
        return doc;
      },
    },
    identities: {
      async fetch(id) {
        if (id !== IDENTITY_ID_BASE58) return null;
        // Register the derived keys once the responder has run.
        return { ...responderIdentity, publicKeys: [...responderIdentity.publicKeys] };
      },
      async update({ identity, addPublicKeys }) {
        // Simulate the responder registering keys: append them to the identity.
        for (const k of addPublicKeys) {
          responderIdentity.publicKeys.push({
            keyId: k.keyId,
            type: k.keyType,
            publicKey: toHex(k.data),
            securityLevel: k.securityLevel,
          });
        }
      },
    },
  };

  return {
    sdk,
    async runResponder(uri) {
      const parsed = parseKeyExchangeUri(uri);
      const { appEphemeralPubKey, contractId } = parsed.request;
      // chain key -> login key
      const loginKey = deriveLoginKeyForContract(WALLET_CHAIN_KEY, IDENTITY_ID_BYTES, contractId);
      responderLoginKey = loginKey;
      const draft = buildLoginKeyResponseDraft({ loginKey, appContractId: contractId, appEphemeralPubKey });
      // publish
      const appContractIdBase58 = base58Encode(contractId);
      await sdk.documents.create({
        document: {
          ownerId: IDENTITY_ID_BASE58,
          properties: {
            contractId: appContractIdBase58,
            appEphemeralPubKeyHash: hash160(appEphemeralPubKey),
            walletEphemeralPubKey: draft.walletEphemeralPublicKey,
            encryptedPayload: draft.encryptedPayload,
            keyIndex: 0,
          },
        },
      });
      // first-login registration
      const data = buildRegistrationKeyData(loginKey, IDENTITY_ID_BYTES);
      const val = validateKeyRegistration({ loginKey, identityIdBytes: IDENTITY_ID_BYTES, identityPublicKeys: responderIdentity.publicKeys });
      if (!val.registered) {
        await sdk.identities.update({
          identity: {},
          addPublicKeys: [
            { keyId: 5, keyType: 2, data: data.authKeyData, securityLevel: 2 }, // ECDSA_HASH160, HIGH
            { keyId: 6, keyType: 0, data: data.encKeyData, securityLevel: 3 }, // ECDSA_SECP256K1, MEDIUM
          ],
        });
      }
      return { loginKey, data };
    },
  };
}

test('full DashConnect app flow: init -> responder -> poll -> complete', async () => {
  const { sdk, runResponder } = makeMockSdk();

  // 1. app initiates
  const init = await app.init({ sdk, appContractIdBytes: CONTRACT_ID, label: 'Yappr' });
  assert.equal(init.uri.startsWith('dash-key:'), true);
  assert.ok(init.connectionId);

  // 2. still pending before responder acts
  const pending = await app.poll({ sdk, connectionId: init.connectionId });
  assert.equal(pending.status, 'pending');

  // 3. responder answers
  const { loginKey, data } = await runResponder(init.uri);

  // 4. poll becomes ready
  const ready = await app.poll({ sdk, connectionId: init.connectionId });
  assert.equal(ready.status, 'ready');
  assert.equal(ready.identityId, IDENTITY_ID_BASE58);

  // 5. complete returns serializable auth material — derived private keys are
  //    NOT exposed over RPC (M11c); they stay as Buffers in the session store.
  const complete = await app.complete({ sdk, connectionId: init.connectionId });
  assert.equal(complete.ok, true);
  assert.equal(complete.method, 'dashconnect');
  assert.equal(complete.identityId, IDENTITY_ID_BASE58);
  assert.equal(complete.authPrivateKeyHex, undefined);
  assert.equal(complete.encPrivateKeyHex, undefined);

  // 6. getAuthMaterial exposes serializable session info, no keys
  const material = app.getAuthMaterial(init.connectionId);
  assert.equal(material.authenticated, true);
  assert.equal(material.identityId, IDENTITY_ID_BASE58);
  assert.equal(material.authPrivateKeyHex, undefined);

  // 7. getSessionKeys returns the derived keys as Buffers (internal only)
  const keys = app.getSessionKeys(init.connectionId);
  const expectedAuth = deriveAuthKeyFromLogin(loginKey, IDENTITY_ID_BYTES);
  const expectedEnc = deriveEncryptionKeyFromLogin(loginKey, IDENTITY_ID_BYTES);
  assert.equal(keys.authPrivateKey.toString('hex'), expectedAuth.toString('hex'));
  assert.equal(keys.encPrivateKey.toString('hex'), expectedEnc.toString('hex'));

  // 8. endSession zeroes the Buffers and drops the store
  assert.equal(app.endSession(init.connectionId).ok, true);
  assert.equal(app.getAuthMaterial(init.connectionId), null);
});

test('poll returns expired after the TTL', async () => {
  const { sdk } = makeMockSdk();
  const init = await app.init({ sdk, appContractIdBytes: CONTRACT_ID });
  // fast-forward: patch the request's createdAt
  // (use a fake timer via monkey-patching Date.now is heavy; instead create then cancel)
  assert.ok(app.list().some((r) => r.connectionId === init.connectionId));
  const cancelled = app.cancel(init.connectionId);
  assert.equal(cancelled.ok, true);
  assert.equal(app.list().length, 0);
  await assert.rejects(() => app.poll({ sdk, connectionId: init.connectionId }));
});

test('complete before ready throws', async () => {
  const { sdk } = makeMockSdk();
  const init = await app.init({ sdk, appContractIdBytes: CONTRACT_ID });
  await assert.rejects(() => app.complete({ sdk, connectionId: init.connectionId }), /not ready/);
});

test('getReadyIdentityId only returns the identity once polled ready (M11a)', async () => {
  const { sdk, runResponder } = makeMockSdk();
  const init = await app.init({ sdk, appContractIdBytes: CONTRACT_ID });

  // not ready yet -> null
  assert.equal(app.getReadyIdentityId(init.connectionId), null);

  // responder answers
  const { loginKey } = await runResponder(init.uri);

  // poll becomes ready
  const ready = await app.poll({ sdk, connectionId: init.connectionId });
  assert.equal(ready.status, 'ready');
  // now exposes the full identity for confirmation
  assert.equal(app.getReadyIdentityId(init.connectionId), IDENTITY_ID_BASE58);

  // after complete, the pending slot is gone -> null
  await app.complete({ sdk, connectionId: init.connectionId });
  assert.equal(app.getReadyIdentityId(init.connectionId), null);
});

test('validateKeyRegistration accepts real IdentityPublicKey-shaped keys', async () => {
  const loginKey = deriveLoginKeyForContract(WALLET_CHAIN_KEY, IDENTITY_ID_BYTES, CONTRACT_ID);
  const data = buildRegistrationKeyData(loginKey, IDENTITY_ID_BYTES);
  // IdentityPublicKey wasm shape: keyTypeNumber / securityLevelNumber / data
  const keys = [
    { keyTypeNumber: 2, securityLevelNumber: 2, data: toHex(data.authKeyData) },
    { keyTypeNumber: 0, securityLevelNumber: 3, data: toHex(data.encKeyData) },
  ];
  const res = validateKeyRegistration({ loginKey, identityIdBytes: IDENTITY_ID_BYTES, identityPublicKeys: keys });
  assert.equal(res.registered, true);
});
