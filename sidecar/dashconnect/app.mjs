//
// app.mjs — DashConnect APP-side initiator for the PyxPass sidecar (M10a).
//
// PyxPass plays the *app* in the yappr key-exchange flow: it emits a `dash-key:`
// QR/deep-link, the user approves it with a real Dash wallet (the responder),
// and PyxPass reads the published `loginKeyResponse`, decrypts the login key,
// and derives the authenticated identity keys.
//
// RPC surface (wired in index.js):
//   dashconnectInit(appContractId, label)          -> { connectionId, uri }
//   dashconnectPoll(connectionId)                  -> { status, ... }
//   dashconnectComplete(connectionId)              -> { ok, method, identityId, loginKeyHash }
//
// dashconnectComplete marks the session DashConnect-authenticated but does NOT
// unlock the vault; the GUI still prompts the master password, then unlock().
//
// Security: pending requests expire after REQUEST_TTL_MS (5 min, countdown in
// the GUI). App ephemeral private keys never leave the sidecar. Never accept a
// login key from a CRITICAL/MASTER responder key (validateKeyRegistration).
//

import { buildKeyExchangeUri } from './uri.mjs';
import {
  decryptLoginKey,
  deriveAuthKeyFromLogin,
  deriveEncryptionKeyFromLogin,
  generateEphemeralKeypair,
  hash160,
  toHex,
} from './crypto.mjs';
import {
  findLoginKeyResponseDocumentId,
  LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
  validateKeyRegistration,
  YAPPR_KEY_EXCHANGE_CONTRACT_ID,
} from './protocol.mjs';

export const REQUEST_TTL_MS = 5 * 60 * 1000; // 5-minute request expiry (security rule)

/** In-flight dash-key: requests keyed by connectionId. */
const pending = new Map();
/** Completed DashConnect sessions (auth material) keyed by connectionId. */
const sessions = new Map();

let seq = 0;
function nextConnectionId() {
  seq += 1;
  return `dc-${Date.now().toString(36)}-${seq}`;
}

/**
 * Initiate a DashConnect login: generate the app ephemeral keypair, build the
 * `dash-key:` URI, and store pending state for poll/complete.
 *
 * @param {object} params
 * @param {object} params.sdk - connected EvoSDK
 * @param {Buffer|string} params.appContractIdBytes - 32-byte app contract id (or base58)
 * @param {string} [params.label] - short human-readable label (<=64 bytes)
 * @param {string} [params.network='testnet']
 * @returns {Promise<{ connectionId: string, uri: string, network: string, label: string|null }>}
 */
export async function init({ sdk, appContractIdBytes, label = null, network = 'testnet' }) {
  const contractIdBytes = normalizeBytes(appContractIdBytes, 32, 'appContractId');
  const { privateKey: appEphemeralPriv, publicKey: appEphemeralPub } = generateEphemeralKeypair();
  const appEphemeralPubKeyHash = toHex(hash160(appEphemeralPub));

  const uri = buildKeyExchangeUri(
    { appEphemeralPubKey: appEphemeralPub, contractId: contractIdBytes, label },
    network,
  );

  const connectionId = nextConnectionId();
  pending.set(connectionId, {
    connectionId,
    appEphemeralPriv,
    appEphemeralPub,
    appEphemeralPubKeyHash,
    contractIdBytes,
    label: label ?? null,
    network,
    createdAt: Date.now(),
    status: 'pending',
  });

  return { connectionId, uri, network, label: label ?? null };
}

/**
 * Poll for a loginKeyResponse addressed to this request. When one arrives,
 * decrypt the login key, derive the auth + enc keys, and validate them on the
 * responder identity. Returns status 'pending' | 'ready' | 'expired'.
 *
 * @returns {Promise<{ status: string, connectionId: string, remainingMs?: number, identityId?: string }>}
 */
export async function poll({ sdk, connectionId }) {
  const req = requirePending(connectionId);
  if (isExpired(req)) {
    req.status = 'expired';
    return { status: 'expired', connectionId, remainingMs: 0 };
  }

  // Find our response on the yappr contract: (contractId, appEphemeralPubKeyHash).
  const docId = await findResponseForRequest(sdk, req);
  if (!docId) {
    return {
      status: 'pending',
      connectionId,
      remainingMs: req.createdAt + REQUEST_TTL_MS - Date.now(),
    };
  }

  const doc = await sdk.documents.get(
    YAPPR_KEY_EXCHANGE_CONTRACT_ID,
    LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
    docId,
  );
  if (!doc) {
    return { status: 'pending', connectionId, remainingMs: req.createdAt + REQUEST_TTL_MS - Date.now() };
  }

  const props = doc.properties;
  // byteArray fields come back as Uint8Array on the wasm Document.
  const walletEphemeralPub = Buffer.from(props.walletEphemeralPubKey);
  const encryptedPayload = Buffer.from(props.encryptedPayload);
  if (walletEphemeralPub.length !== 33) throw new Error('Invalid wallet ephemeral pub key length');

  const loginKey = decryptLoginKey(encryptedPayload, req.appEphemeralPriv, walletEphemeralPub);
  const responderIdentityId = doc.ownerId.toString();

  // Validate the derived keys are actually registered on the responder identity.
  const responderIdentity = await sdk.identities.fetch(responderIdentityId);
  const identityIdBytes = identityToBytes(responderIdentityId);
  const validation = validateKeyRegistration({
    loginKey,
    identityIdBytes,
    identityPublicKeys: responderIdentity?.publicKeys ?? [],
  });
  if (!validation.registered) {
    throw new Error('loginKeyResponse did not yield registered login keys on responder identity');
  }

  const authPriv = deriveAuthKeyFromLogin(loginKey, identityIdBytes);
  const encPriv = deriveEncryptionKeyFromLogin(loginKey, identityIdBytes);

  req.status = 'ready';
  // The raw login key is only needed to derive auth/enc — zero it now that
  // both derived keys are in hand (M11c).
  req.loginKey = loginKey;
  req.authPrivateKey = authPriv;
  req.encPrivateKey = encPriv;
  req.responderIdentityId = responderIdentityId;
  clearSensitive([loginKey]);
  req.loginKey = undefined;

  // The app ephemeral private key is no longer needed once the login key is
  // decrypted — zero it now.
  clearSensitive([req.appEphemeralPriv]);
  req.appEphemeralPriv = undefined;

  return { status: 'ready', connectionId, identityId: responderIdentityId };
}

/**
 * Complete the DashConnect login: return the derived auth identity (keys stay
 * in the sidecar). Marks the session DashConnect-authenticated; the vault is
 * NOT unlocked here.
 *
 * @returns {Promise<{ ok: boolean, method: string, identityId: string, loginKeyHash: string }>}
 */
export async function complete({ sdk, connectionId }) {
  const req = requirePending(connectionId);
  if (isExpired(req)) {
    req.status = 'expired';
    throw new Error('DashConnect request expired');
  }
  if (req.status !== 'ready') {
    throw new Error(`DashConnect request not ready (status: ${req.status}); call dashconnectPoll first`);
  }

  const loginKeyHash = toHex(hash160(req.authPrivateKey));
  const result = {
    ok: true,
    method: 'dashconnect',
    identityId: req.responderIdentityId,
    loginKeyHash,
  };

  // Move the request into the session store. Derived keys are kept as zeroable
  // Buffers (NOT hex strings) so they can be wiped on lock/end (M11c).
  sessions.set(connectionId, {
    identityId: req.responderIdentityId,
    authPrivateKey: req.authPrivateKey,
    encPrivateKey: req.encPrivateKey,
    loginKeyHash,
    completedAt: Date.now(),
  });

  pending.delete(connectionId);
  return result;
}

/**
 * Read a completed DashConnect session's serializable auth material.
 * Derived private keys are intentionally NOT returned here (they stay as
 * Buffers in the session store, retrievable only via getSessionKeys for
 * internal use). Keeps them off the JSON-RPC surface (M11c).
 */
export function getAuthMaterial(connectionId) {
  const s = sessions.get(connectionId);
  if (!s) return null;
  return {
    identityId: s.identityId,
    loginKeyHash: s.loginKeyHash,
    authenticated: true,
  };
}

/**
 * Internal: retrieve the derived session private keys as Buffers (zeroable).
 * Only for in-process use; never send these over RPC.
 * @returns {{ authPrivateKey: Buffer, encPrivateKey: Buffer }|null}
 */
export function getSessionKeys(connectionId) {
  const s = sessions.get(connectionId);
  if (!s) return null;
  return { authPrivateKey: s.authPrivateKey, encPrivateKey: s.encPrivateKey };
}

/**
 * End a DashConnect session: zero the derived key Buffers and drop the store.
 * Called on vault lock so no auth material survives in memory (M11c).
 */
export function endSession(connectionId) {
  const s = sessions.get(connectionId);
  if (s) {
    clearSensitive([s.authPrivateKey, s.encPrivateKey]);
    sessions.delete(connectionId);
  }
  return { ok: true };
}

/** Cancel a pending request (user declined / QR dismissed). */
export function cancel(connectionId) {
  const req = pending.get(connectionId);
  if (req) {
    clearSensitive([req.appEphemeralPriv]);
    pending.delete(connectionId);
  }
  return { ok: true };
}

/** List pending requests (for the GUI's request tray). */
export function list() {
  const now = Date.now();
  const out = [];
  for (const req of pending.values()) {
    out.push({
      connectionId: req.connectionId,
      status: isExpired(req) ? 'expired' : req.status,
      label: req.label,
      network: req.network,
      remainingMs: req.createdAt + REQUEST_TTL_MS - now,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function requirePending(connectionId) {
  const req = pending.get(connectionId);
  if (!req) throw new Error(`Unknown DashConnect connection: ${connectionId}`);
  return req;
}

function isExpired(req) {
  return Date.now() - req.createdAt > REQUEST_TTL_MS;
}

/** Query the yappr contract for our specific response doc id. */
async function findResponseForRequest(sdk, req) {
  // appEphemeralPubKeyHash is a byteArray(20) field; the SDK stores/compares
  // it in base64, so the where value must be base64 (not hex).
  const appEphemeralPubKeyHashB64 = Buffer.from(hash160(req.appEphemeralPub)).toString('base64');
  const where = [
    ['contractId', '==', base58Encode(req.contractIdBytes)],
    ['appEphemeralPubKeyHash', '==', appEphemeralPubKeyHashB64],
  ];
  const result = await sdk.documents.query({
    dataContractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
    documentTypeName: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
    where,
    limit: 1,
  });
  const first = firstDoc(result);
  return first?.getDocumentId?.() ?? first?.id?.toString?.() ?? first?.$id ?? null;
}

function firstDoc(result) {
  if (result instanceof Map) {
    for (const [, doc] of result) return doc;
    return undefined;
  }
  if (Array.isArray(result)) return result[0];
  if (result && Array.isArray(result.documents)) return result.documents[0];
  return undefined;
}

function normalizeBytes(input, expectedLen, name) {
  let bytes = input;
  if (typeof input === 'string') {
    const decoded = base58Decode(input);
    if (decoded.length !== expectedLen) {
      // maybe hex?
      const hex = fromHexStrict(input);
      if (hex && hex.length === expectedLen) bytes = hex;
      else throw new Error(`${name} must be ${expectedLen} bytes`);
    } else {
      bytes = decoded;
    }
  }
  if (bytes.length !== expectedLen) throw new Error(`${name} must be ${expectedLen} bytes`);
  return bytes;
}

function fromHexStrict(hex) {
  if (!/^[0-9a-fA-F]{2,}$/.test(hex) || hex.length % 2 !== 0) return null;
  return Buffer.from(hex, 'hex');
}

function fromHexOrThrow(value, name) {
  if (typeof value !== 'string') throw new Error(`Missing ${name} in loginKeyResponse`);
  const bytes = Buffer.from(value, 'hex');
  if (bytes.length * 2 !== value.length) throw new Error(`Invalid hex for ${name}`);
  return bytes;
}

function identityToBytes(identityIdBase58) {
  return base58Decode(identityIdBase58);
}

function clearSensitive(bufs) {
  for (const b of bufs) if (b?.fill) b.fill(0);
}

import { base58Decode, base58Encode } from './base58.mjs';

export default {
  REQUEST_TTL_MS,
  cancel,
  complete,
  endSession,
  getAuthMaterial,
  getSessionKeys,
  init,
  list,
  poll,
};
