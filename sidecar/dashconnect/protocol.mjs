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
  const buf = key.toBuffer();
  if (buf.length !== 32) throw new Error(`Unexpected private key length: ${buf.length}`);
  return buf;
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

  const priv = walletEphemeralPrivateKey ?? generateEphemeralKeypair().privateKey;
  const walletEphemeralPublicKey = compressedPublicKey(priv);
  const encryptedPayload = encryptLoginKey(loginKey, priv, appEphemeralPubKey, randomNonce());

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
  return {
    authPublicKey: authPub,
    authKeyData: hash160(authPub), // ECDSA_HASH160 stores hash160 of the pub key
    encPublicKey: encPub,
    encKeyData: encPub, // ECDSA_SECP256K1 stores the pub key directly
  };
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

  const pubKeys = identityPublicKeys.map((k) => ({
    type: k.type,
    publicKey: typeof k.publicKey === 'string' ? k.publicKey.toLowerCase() : toHex(k.publicKey),
    securityLevel: k.securityLevel,
  }));

  const authenticationPresent = pubKeys.some(
    (k) =>
      k.publicKey === authHash && // ECDSA_HASH160 keys are stored by hash160
      (k.securityLevel === 1 || k.securityLevel === 0), // HIGH or MASTER
  );
  const encryptionPresent = pubKeys.some(
    (k) => k.publicKey === encPubHex && k.type === 4, // ECDSA_SECP256K1 (DIP-9 type 4)
  );

  return {
    registered: authenticationPresent && encryptionPresent,
    authenticationPresent,
    encryptionPresent,
  };
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
  const response = await sdk.documents.query({
    contractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
    documentType: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
    where: clause,
    limit: 1,
  });
  const docs = response?.documents ?? response;
  const first = Array.isArray(docs) ? docs[0] : null;
  return first?.$id ?? first?.getDocumentId?.() ?? null;
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
  loginKeyResponseWhereClause,
  publishLoginKeyResponse,
  randomNonce,
  registerLoginKeys,
  validateKeyRegistration,
  wifToPrivateKeyBytes,
  injectPrivateKey,
};
