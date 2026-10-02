//
// protocol.mjs — wallet-side DashConnect key-exchange responder.
//
// PyxPass owns the identity and its keys, so it plays the *wallet* role in the
// yappr key-exchange flow. This module turns a received `dash-key:` request
// into a published `loginKeyResponse` document on the yappr key-exchange
// contract, and validates first-login key registration (`dash-st:`).
//
// Crypto matches the dash wallets byte-for-byte (see crypto.mjs).
//
// Response document (published to yappr key-exchange contract, doc type
// "loginKeyResponse", unique index (contractId, appEphemeralPubKeyHash)):
//   {
//     contractId:            appContractId base58,
//     appEphemeralPubKeyHash: hash160(appEphemeralPubKey).toHex(),
//     walletEphemeralPubKey:  hex,
//     encryptedPayload:       hex (nonce||ct||tag, 60 bytes),
//     keyIndex:               0,
//   }
//

import crypto from 'node:crypto';
import {
  clearSensitiveBytes,
  compressedPublicKey,
  deriveAuthKeyFromLogin,
  deriveEncryptionKeyFromLogin,
  deriveLoginKey,
  encryptLoginKey,
  generateEphemeralKeypair,
  hash160,
  toHex,
} from './crypto.mjs';
import { base58Decode, base58Encode } from './base58.mjs';

/** The pinned TESTNET yappr key-exchange contract (loginKeyResponse docs). */
export const YAPPR_KEY_EXCHANGE_CONTRACT_ID = '7UaqHGBJBbRLJ4fUWS45cnud8PPUugJWoGTt1SKwHJ2P';
export const LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE = 'loginKeyResponse';
export const LOGIN_KEY_DERIVATION_KEY_INDEX = 0; // auth-chain key index 0

/**
 * Decode a WIF private key string to its raw 32-byte private key.
 * Requires the evo-sdk PrivateKey to have been injected (see injectPrivateKey).
 * @returns {Buffer}
 */
export function wifToPrivateKeyBytes(wif) {
  if (!privateKeyClass) {
    throw new Error('PrivateKey not injected; call injectPrivateKey() first (sidecar)');
  }
  const key = privateKeyClass.fromWIF(wif);
  const bytes = key.toBytes();
  if (bytes.length !== 32) throw new Error(`Unexpected private key length: ${bytes.length}`);
  return Buffer.from(bytes);
}

let privateKeyClass = undefined;

/**
 * Inject the evo-sdk PrivateKey class so this module can decode WIF keys.
 * The sidecar calls this once at startup; tests can skip it.
 */
export function injectPrivateKey(PrivateKeyClass) {
  privateKeyClass = PrivateKeyClass;
}

/**
 * Derive the login key for a (wallet identity, app contract) pair.
 *   loginKey = HKDF(chainKey, identityId, "dash:login-key:v1" || contractId)
 * chainKey = the identity's auth-chain private key bytes (key index 0).
 * @param {Buffer} chainKeyPrivateBytes - raw 32-byte auth-chain private key
 * @param {Buffer} identityIdBytes - raw 32-byte identity id
 * @param {Buffer} appContractIdBytes - raw 32-byte app contract id
 * @returns {Buffer} 32-byte login key
 */
export function deriveLoginKeyForContract(chainKeyPrivateBytes, identityIdBytes, appContractIdBytes) {
  return deriveLoginKey(chainKeyPrivateBytes, identityIdBytes, appContractIdBytes);
}

/**
 * Build the loginKeyResponse draft for a dash-key: request.
 * Matches the wallet's buildLoginKeyResponseDraft.
 * @param {object} params
 * @param {Buffer} params.loginKey - 32-byte login key
 * @param {Buffer} params.appContractId - raw 32-byte app contract id
 * @param {Buffer} params.appEphemeralPubKey - raw 33-byte compressed app ephemeral pub
 * @param {Buffer} [params.walletEphemeralPrivateKey] - optional (generated if absent)
 * @returns {{ properties: object, walletEphemeralPublicKey: Buffer, encryptedPayload: Buffer, walletEphemeralPrivateKey: Buffer }}
 */
export function buildLoginKeyResponseDraft({
  loginKey,
  appContractId,
  appEphemeralPubKey,
  walletEphemeralPrivateKey,
}) {
  if (appEphemeralPubKey.length !== 33) {
    throw new Error(`Invalid ephemeral public key length: expected 33, got ${appEphemeralPubKey.length}`);
  }
  const appEphemeralPubKeyHash = hash160(appEphemeralPubKey);
  if (appEphemeralPubKeyHash.length !== 20) throw new Error('Invalid hash160');

  const generatedPriv = walletEphemeralPrivateKey == null;
  const priv = walletEphemeralPrivateKey ?? generateEphemeralKeypair().privateKey;
  const walletEphemeralPublicKey = compressedPublicKey(priv);
  const encryptedPayload = encryptLoginKey(loginKey, priv, appEphemeralPubKey, randomNonce());

  // M11c: the wallet ephemeral private key is spent after encryption — zero it
  // now if we generated it. A caller-provided key stays caller-owned.
  if (generatedPriv) clearSensitiveBytes(priv);

  const properties = {
    contractId: base58Encode(appContractId),
    appEphemeralPubKeyHash: toHex(appEphemeralPubKeyHash),
    walletEphemeralPubKey: toHex(walletEphemeralPublicKey),
    encryptedPayload: toHex(encryptedPayload),
    keyIndex: LOGIN_KEY_DERIVATION_KEY_INDEX,
  };

  return { properties, walletEphemeralPublicKey, encryptedPayload, walletEphemeralPrivateKey: priv };
}

/** 12-byte random nonce. */
export function randomNonce() {
  return crypto.randomBytes(12);
}

/**
 * Where-clause to find the existing loginKeyResponse for a (wallet, app).
 * Unique index is (contractId, appEphemeralPubKeyHash); we look up by owner +
 * app contract so a re-login replaces the same slot.
 */
export function loginKeyResponseWhereClause(identityIdBase58, appContractIdBytes) {
  return [
    ['$ownerId', '==', identityIdBase58],
    ['contractId', '==', base58Encode(appContractIdBytes)],
  ];
}

/**
 * Derive the public-key material needed to register the login-derived keys on
 * the responder identity (first-login registration, dash-st:).
 *
 * - auth key: ECDSA_HASH160, AUTHENTICATION/HIGH, data = hash160(authPub)
 * - enc  key: ECDSA_SECP256K1, ENCRYPTION/MEDIUM, data = encPub
 *
 * Pure — no SDK types required, so it is unit-testable.
 * @param {Buffer} loginKey - 32-byte login key
 * @param {Buffer} identityIdBytes - raw 32-byte identity id
 * @returns {{ authPublicKey: Buffer, authKeyData: Buffer, encPublicKey: Buffer, encKeyData: Buffer }}
 */
export function buildRegistrationKeyData(loginKey, identityIdBytes) {
  const authPriv = deriveAuthKeyFromLogin(loginKey, identityIdBytes);
  const encPriv = deriveEncryptionKeyFromLogin(loginKey, identityIdBytes);
  const authPub = compressedPublicKey(authPriv);
  const encPub = compressedPublicKey(encPriv);
  const result = {
    authPublicKey: authPub,
    authKeyData: hash160(authPub), // ECDSA_HASH160 stores hash160 of the pub key
    encPublicKey: encPub,
    encKeyData: encPub, // ECDSA_SECP256K1 stores the pub key directly
  };
  // M11c: zero the derived private-key intermediates; only public material is returned.
  clearSensitiveBytes(authPriv);
  clearSensitiveBytes(encPriv);
  return result;
}

/**
 * Validate a first-login key registration: confirm the derived auth + enc keys
 * are actually on the responder identity. Pure over the identity's public keys.
 * @param {object} params
 * @param {Buffer} params.loginKey - 32-byte login key
 * @param {Buffer} params.identityIdBytes
 * @param {Array<{id: number, type: string|number, publicKey: string|Buffer, purpose?: number, securityLevel?: number}>} params.identityPublicKeys
 * @returns {{ registered: boolean, authenticationPresent: boolean, encryptionPresent: boolean }}
 */
export function validateKeyRegistration({ loginKey, identityIdBytes, identityPublicKeys }) {
  const authPriv = deriveAuthKeyFromLogin(loginKey, identityIdBytes);
  const encPriv = deriveEncryptionKeyFromLogin(loginKey, identityIdBytes);
  const authPub = compressedPublicKey(authPriv);
  const encPub = compressedPublicKey(encPriv);
  const authHash = toHex(hash160(authPub));
  const encPubHex = toHex(encPub);

  // evo-sdk enums: KeyType {ECDSA_SECP256K1:0, ECDSA_HASH160:2},
  // SecurityLevel {MASTER:0, CRITICAL:1, HIGH:2, MEDIUM:3}.
  const SEC_LEVEL = { MASTER: 0, CRITICAL: 1, HIGH: 2, MEDIUM: 3 };
  const normSec = (v) =>
    typeof v === 'number' ? v : SEC_LEVEL[String(v).toUpperCase()] ?? -1;
  const normHex = (v) =>
    v == null
      ? ''
      : v instanceof Uint8Array
        ? Buffer.from(v).toString('hex')
        : String(v).toLowerCase();

  // Normalize both plain-object fixtures (tests) and real IdentityPublicKey
  // wasm objects (which expose keyTypeNumber / securityLevelNumber / data).
  const pubKeys = identityPublicKeys.map((k) => ({
    type: String(k.type ?? k.keyTypeNumber),
    publicKey: normHex(k.publicKey ?? k.data),
    securityLevel: normSec(k.securityLevel ?? k.securityLevelNumber),
  }));

  // ECDSA_HASH160 (type 2) auth keys are stored as hash160 of the pub key;
  // require HIGH (2) or MASTER (0).
  const authenticationPresent = pubKeys.some(
    (k) =>
      k.type === '2' && // ECDSA_HASH160
      k.publicKey === authHash &&
      (k.securityLevel === 2 || k.securityLevel === 0),
  );
  // ECDSA_SECP256K1 (type 0) encryption key, MEDIUM (3) or stronger.
  const encryptionPresent = pubKeys.some(
    (k) =>
      k.type === '0' && // ECDSA_SECP256K1
      k.publicKey === encPubHex &&
      (k.securityLevel === 3 || k.securityLevel === 2 || k.securityLevel === 0),
  );

  // M11c: zero derived private-key intermediates after use.
  clearSensitiveBytes(authPriv);
  clearSensitiveBytes(encPriv);
  clearSensitiveBytes(authPub);
  clearSensitiveBytes(encPub);

  return {
    registered: authenticationPresent && encryptionPresent,
    authenticationPresent,
    encryptionPresent,
  };
}

/**
 * M11b: check whether the login key derived from a loginKeyResponse has been
 * REVOKED on-chain. The wallet re-derives the SAME key every login
 * (HKDF(chainKey, identity, "dash:login-key:v1" || contractId)), so once the
 * user disables it on the identity, every future login from that wallet yields
 * the same disabled key. We must refuse to accept it (RevokedWalletKey) rather
 * than silently re-authenticate with a key the user revoked.
 *
 * Returns true when either the derived auth or enc public key is present on the
 * identity but marked disabled (disabledAt set).
 *
 * @param {{loginKey: Buffer, identityIdBytes: Buffer, identityPublicKeys: Array}} params
 * @returns {boolean} true if the derived login key was revoked
 */
export function isLoginKeyRevoked({ loginKey, identityIdBytes, identityPublicKeys }) {
  const authPriv = deriveAuthKeyFromLogin(loginKey, identityIdBytes);
  const encPriv = deriveEncryptionKeyFromLogin(loginKey, identityIdBytes);
  const authPub = compressedPublicKey(authPriv);
  const encPub = compressedPublicKey(encPriv);
  const authHash = toHex(hash160(authPub));
  const encPubHex = toHex(encPub);

  const normHex = (v) =>
    v == null
      ? ''
      : v instanceof Uint8Array
        ? Buffer.from(v).toString('hex')
        : String(v).toLowerCase();

  // disabledAt is a method on real IdentityPublicKey wasm objects; a property on
  // plain fixtures. Returns undefined (or null/0) when NOT disabled.
  const disabledAt = (k) => {
    const d = typeof k.disabledAt === 'function' ? k.disabledAt() : k.disabledAt;
    return d == null ? null : d;
  };

  const pubKeys = identityPublicKeys.map((k) => ({
    type: String(k.type ?? k.keyTypeNumber),
    publicKey: normHex(k.publicKey ?? k.data),
    disabled: disabledAt(k) != null && disabledAt(k) !== 0,
  }));

  // Auth key revoked: ECDSA_HASH160 (type 2) matching the derived auth hash and disabled.
  const authRevoked = pubKeys.some(
    (k) => k.type === '2' && k.publicKey === authHash && k.disabled,
  );
  // Enc key revoked: ECDSA_SECP256K1 (type 0) matching the derived enc pub and disabled.
  const encRevoked = pubKeys.some(
    (k) => k.type === '0' && k.publicKey === encPubHex && k.disabled,
  );

  // M11c: zero derived private-key intermediates after use.
  clearSensitiveBytes(authPriv);
  clearSensitiveBytes(encPriv);
  clearSensitiveBytes(authPub);
  clearSensitiveBytes(encPub);

  return authRevoked || encRevoked;
}

/**
 * Publish a loginKeyResponse document to the yappr key-exchange contract,
 * create-or-replace on the (ownerId, contractId) unique slot.
 * Thin SDK adapter; the pure draft is buildLoginKeyResponseDraft.
 *
 * @param {object} params
 * @param {object} params.sdk - connected EvoSDK
 * @param {Buffer} params.identityIdBytes - raw 32-byte responder identity id
 * @param {Buffer} params.appContractIdBytes - raw 32-byte app contract id
 * @param {object} params.properties - the loginKeyResponse document properties
 * @param {object} params.signer - IdentitySigner (auth key) for the doc
 * @returns {Promise<string>} the document id
 */
export async function publishLoginKeyResponse({
  sdk,
  identityIdBytes,
  appContractIdBytes,
  properties,
  signer,
}) {
  const identityIdBase58 = base58Encode(identityIdBytes);
  const contractIdBase58 = base58Encode(appContractIdBytes);

  // Look up an existing response for this (owner, app contract) to replace.
  const existing = await findLoginKeyResponseDocumentId(sdk, identityIdBase58, contractIdBase58);
  if (existing) {
    await sdk.documents.replace({
      ownerIdentityId: identityIdBase58,
      contractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
      documentType: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
      documentId: existing,
      properties,
      signer,
    });
    return existing;
  }

  try {
    const doc = await sdk.documents.create({
      ownerIdentityId: identityIdBase58,
      contractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
      documentType: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
      properties,
      signer,
    });
    return doc?.getDocumentId?.() ?? doc?.$id;
  } catch {
    // Race: the doc appeared between lookup and create — re-check, then replace.
    const raced = await findLoginKeyResponseDocumentId(sdk, identityIdBase58, contractIdBase58);
    if (raced) {
      await sdk.documents.replace({
        ownerIdentityId: identityIdBase58,
        contractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
        documentType: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
        documentId: raced,
        properties,
        signer,
      });
      return raced;
    }
    throw new Error(`Failed to publish loginKeyResponse for contract ${contractIdBase58}`);
  }
}

/**
 * Locate the existing loginKeyResponse document id for (owner, app contract).
 * @returns {Promise<string|null>}
 */
export async function findLoginKeyResponseDocumentId(sdk, identityIdBase58, appContractIdBase58) {
  const appContractIdBytes = base58Decode(appContractIdBase58);
  const clause = loginKeyResponseWhereClause(identityIdBase58, appContractIdBytes);
  const result = await sdk.documents.query({
    dataContractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
    documentTypeName: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
    where: clause,
    limit: 1,
  });
  const first = firstDoc(result);
  return first?.getDocumentId?.() ?? first?.$id ?? null;
}

/** Take the first Document from a query result (Map or array). */
export function firstDoc(result) {
  if (result instanceof Map) {
    for (const [, doc] of result) return doc;
    return undefined;
  }
  if (Array.isArray(result)) return result[0];
  if (result && Array.isArray(result.documents)) return result.documents[0];
  if (result && result.documents instanceof Map) {
    for (const [, doc] of result.documents) return doc;
    return undefined;
  }
  return undefined;
}

/**
 * First-login registration: add the login-derived auth (ECDSA_HASH160/HIGH)
 * and enc (ECDSA_SECP256K1/MEDIUM) keys to the responder identity via an
 * IdentityUpdate signed by the master key.
 * Thin SDK adapter; pure key material is buildRegistrationKeyData.
 *
 * @param {object} params
 * @param {object} params.sdk - connected EvoSDK
 * @param {object} params.identity - the fetched Identity
 * @param {object} params.masterSigner - IdentitySigner holding the master key
 * @param {Buffer} params.authKeyData - hash160 of the auth pub key
 * @param {Buffer} params.encKeyData - the enc pub key
 * @param {object} params.sdkTypes - { IdentityPublicKeyInCreation, KeyType, Purpose, SecurityLevel }
 * @param {[number, number]} [params.keyIds] - key ids for [auth, enc] (default [5, 6])
 * @param {object} [params.settings] - PutSettings
 */
export async function registerLoginKeys({
  sdk,
  identity,
  masterSigner,
  authKeyData,
  encKeyData,
  sdkTypes,
  keyIds = [5, 6],
  settings,
}) {
  const { IdentityPublicKeyInCreation, KeyType, Purpose, SecurityLevel } = sdkTypes;
  const [authKeyId, encKeyId] = keyIds;

  const addPublicKeys = [
    new IdentityPublicKeyInCreation({
      keyId: authKeyId,
      purpose: Purpose.AUTHENTICATION,
      securityLevel: SecurityLevel.HIGH,
      keyType: KeyType.ECDSA_HASH160,
      data: authKeyData,
    }),
    new IdentityPublicKeyInCreation({
      keyId: encKeyId,
      purpose: Purpose.ENCRYPTION,
      securityLevel: SecurityLevel.MEDIUM,
      keyType: KeyType.ECDSA_SECP256K1,
      data: encKeyData,
    }),
  ];

  await sdk.identities.update({ identity, addPublicKeys, signer: masterSigner, settings });
  return { authKeyId, encKeyId };
}

export default {
  YAPPR_KEY_EXCHANGE_CONTRACT_ID,
  LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
  LOGIN_KEY_DERIVATION_KEY_INDEX,
  buildLoginKeyResponseDraft,
  buildRegistrationKeyData,
  deriveLoginKeyForContract,
  findLoginKeyResponseDocumentId,
  firstDoc,
  loginKeyResponseWhereClause,
  publishLoginKeyResponse,
  randomNonce,
  registerLoginKeys,
  validateKeyRegistration,
  wifToPrivateKeyBytes,
  injectPrivateKey,
};
