#!/usr/bin/env node
//
// e2e/wallet-responder.mjs — scripted DashConnect WALLET responder (M10 e2e).
//
// Plays the Dash wallet side of the yappr key-exchange against a `dash-key:`
// URI emitted by the PyxPass sidecar (the app side). Uses a SEPARATE identity
// derived from the same mnemonic (identityIndex, default 1) so the e2e is
// self-contained and independent of the app-side identity.
//
// Flow:
//   1. parse the dash-key: URI
//   2. chain key = responder identity auth-chain key index 0 (master key)
//   3. loginKey = HKDF(chainKey, responderIdentityId, "dash:login-key:v1" || contractId)
//   4. build loginKeyResponse (encrypt login key under wallet ephemeral)
//   5. publish to yappr key-exchange contract (create-or-replace)
//   6. if --register: first-login registration — IdentityUpdate adding the
//      derived auth (ECDSA_HASH160/HIGH) + enc (ECDSA_SECP256K1/MEDIUM) keys
//
// Usage:
//   node e2e/wallet-responder.mjs --uri "dash-key:..." [--identity-index 1] [--register]
//
// Network + mnemonic come from config/testnet.json / PLATFORM_MNEMONIC env.
//

import { readFile } from 'node:fs/promises';
import { createClient, IdentityKeyManager } from '../setupDashClient.mjs';
import {
  buildLoginKeyResponseDraft,
  buildRegistrationKeyData,
  deriveLoginKeyForContract,
  injectPrivateKey,
  validateKeyRegistration,
  YAPPR_KEY_EXCHANGE_CONTRACT_ID,
  LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
} from '../dashconnect/protocol.mjs';
import { parseKeyExchangeUri } from '../dashconnect/uri.mjs';
import { toHex, hash160 } from '../dashconnect/crypto.mjs';
import { base58Encode } from '../dashconnect/base58.mjs';
import { Document, PrivateKey } from '@dashevo/evo-sdk';

injectPrivateKey(PrivateKey);

function arg(name, def = undefined) {
  const idx = process.argv.indexOf(`--${name}`);
  return idx === -1 ? def : process.argv[idx + 1];
}
function flag(name) {
  return process.argv.includes(`--${name}`);
}

async function main() {
  const uri = arg('uri');
  const identityIndex = Number(arg('identity-index', '1'));
  const doRegister = flag('register');

  if (!uri) {
    console.error('usage: node e2e/wallet-responder.mjs --uri "dash-key:..." [--identity-index 1] [--register]');
    process.exit(1);
  }

  const parsed = parseKeyExchangeUri(uri);
  if (!parsed) {
    console.error('invalid dash-key: URI');
    process.exit(1);
  }
  const { appEphemeralPubKey, contractId, label } = parsed.request;
  console.log(`[responder] network=${parsed.network} label=${label ?? '(none)'}`);
  console.log(`[responder] contractId=${base58Encode(contractId)}`);
  console.log(`[responder] appEphemeralPub=${toHex(appEphemeralPubKey)}`);

  const config = JSON.parse(await readFile(new URL('../../config/testnet.json', import.meta.url), 'utf8'));
  const network = config.network ?? 'testnet';
  const mnemonic = process.env.PLATFORM_MNEMONIC || config.mnemonic;

  const sdk = await createClient(network);

  // Responder identity (independent from app-side identity index).
  const keyManager = await IdentityKeyManager.create({ sdk, mnemonic, network, identityIndex });
  const identity = await sdk.identities.fetch(keyManager.id);
  const identityIdBytes = identity.id.toBytes();
  console.log(`[responder] identityId=${identity.id.toString()}`);

  // chain key = master key (keyId 0) private bytes.
  const chainKey = wifToPrivate(keyManager.keys.master.privateKeyWif);
  const loginKey = deriveLoginKeyForContract(chainKey, identityIdBytes, contractId);
  console.log(`[responder] loginKey derived (${toHex(loginKey).slice(0, 16)}…)`);

  // Build the loginKeyResponse (encrypt login key under wallet ephemeral).
  const draft = buildLoginKeyResponseDraft({
    loginKey,
    appContractId: contractId,
    appEphemeralPubKey,
  });
  const appEphemeralPubKeyHashBytes = hash160(appEphemeralPubKey);
  // Where-clause value for the byteArray field: base64 (what the SDK stores).
  const appEphemeralPubKeyHash = Buffer.from(appEphemeralPubKeyHashBytes).toString('base64');
  const appContractIdBase58 = base58Encode(contractId);

  // Publish create-or-replace on (contractId, appEphemeralPubKeyHash).
  const { identityKey, signer } = await keyManager.getAuth();
  const buildDoc = (ownerId) =>
    new Document({
      documentTypeName: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
      dataContractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
      ownerId,
      properties: {
        contractId: appContractIdBase58,
        // byteArray fields must be raw bytes; the SDK base64-encodes them.
        appEphemeralPubKeyHash: appEphemeralPubKeyHashBytes,
        walletEphemeralPubKey: draft.walletEphemeralPublicKey,
        encryptedPayload: draft.encryptedPayload,
        keyIndex: 0,
      },
    });

  const publish = () =>
    sdk.documents.create({
      document: buildDoc(identity.id),
      identityKey,
      signer,
    });

  // create-or-replace with DAPI-lag tolerance.
  const publishOrReplace = () =>
    withRetry(async () => {
      try {
        const doc = await publish();
        return doc?.id?.toString?.() ?? doc?.$id ?? doc;
      } catch (err) {
        // create raced: replace the existing doc via the valid index.
        console.log(`[responder] create raced (${err.message}); replacing`);
        // The contract's byOwnerAndContract index is unique on
        // ($ownerId, contractId): an owner has ONE response per app contract.
        // Find that doc so we can replace it with the current request's values.
        const existing = await sdk.documents.query({
          dataContractId: YAPPR_KEY_EXCHANGE_CONTRACT_ID,
          documentTypeName: LOGIN_KEY_EXCHANGE_DOCUMENT_TYPE,
          where: [
            ['$ownerId', '==', identity.id.toString()],
            ['contractId', '==', appContractIdBase58],
          ],
          limit: 1,
        });
        const first = firstOf(existing);
        if (!first) {
          // DAPI read-lag: the create validated against chain state but the
          // read node hasn't caught up. Retry from the top.
          throw new Error('response doc not readable yet (DAPI lag)');
        }
        first.properties = {
          contractId: appContractIdBase58,
          appEphemeralPubKeyHash,
          walletEphemeralPubKey: toHex(draft.walletEphemeralPublicKey),
          encryptedPayload: toHex(draft.encryptedPayload),
          keyIndex: 0,
        };
        first.revision = (first.revision ?? 0n) + 1n;
        await sdk.documents.replace({ document: first, identityKey, signer });
        return first.id.toString();
      }
    }, 'publish');

  const responseId = await publishOrReplace();
  console.log(`[responder] loginKeyResponse published: ${responseId}`);

  // First-login registration (dash-st:): add derived auth + enc keys.
  if (doRegister) {
    const data = buildRegistrationKeyData(loginKey, identityIdBytes);
    await withRetry(async () => {
      // Re-fetch identity fresh each try (register may have landed).
      const freshIdentity = await sdk.identities.fetch(keyManager.id);
      const validation = validateKeyRegistration({
        loginKey,
        identityIdBytes,
        identityPublicKeys: freshIdentity.publicKeys,
      });
      if (validation.registered) {
        console.log('[responder] login keys already registered; skipping');
        return;
      }
      const { IdentityPublicKeyInCreation, KeyType, Purpose, SecurityLevel } = await import('@dashevo/evo-sdk');
      const { deriveAuthKeyFromLogin, deriveEncryptionKeyFromLogin } =
        await import('../dashconnect/crypto.mjs');
      const authPriv = deriveAuthKeyFromLogin(loginKey, identityIdBytes);
      const encPriv = deriveEncryptionKeyFromLogin(loginKey, identityIdBytes);
      const authWif = PrivateKey.fromBytes(new Uint8Array(authPriv), network).toWIF();
      const encWif = PrivateKey.fromBytes(new Uint8Array(encPriv), network).toWIF();
      // A new key signs its own registration, so the signer must hold the
      // derived auth + enc private keys alongside the master key.
      const { identity: masterIdentity, signer: masterSigner } =
        await keyManager.getMaster([authWif, encWif]);
      const used = new Set(freshIdentity.publicKeys.map((k) => k.keyId));
      let nextId = 5;
      while (used.has(nextId)) nextId += 1;
      const authId = nextId++;
      const encId = nextId++;

      try {
        await sdk.identities.update({
          identity: masterIdentity,
          addPublicKeys: [
            new IdentityPublicKeyInCreation({
              keyId: authId,
              purpose: Purpose.AUTHENTICATION,
              securityLevel: SecurityLevel.HIGH,
              keyType: KeyType.ECDSA_HASH160,
              data: data.authKeyData,
            }),
            new IdentityPublicKeyInCreation({
              keyId: encId,
              purpose: Purpose.ENCRYPTION,
              securityLevel: SecurityLevel.MEDIUM,
              keyType: KeyType.ECDSA_SECP256K1,
              data: data.encKeyData,
            }),
          ],
          signer: masterSigner,
        });
        console.log(`[responder] registered login keys (auth#${authId}, enc#${encId})`);
      } catch (err) {
        // Idempotent: a stale identity fetch may miss already-registered keys.
        // If the unique key already exists, registration already landed.
        const msg = String(err?.message ?? err);
        if (/already exists|unique set|already exist/i.test(msg)) {
          console.log('[responder] login keys already registered (idempotent); skipping');
        } else {
          throw err;
        }
      }
    }, 'register');
  }

  console.log('[responder] done');
}

function firstOf(result) {
  if (result instanceof Map) { for (const [, d] of result) return d; return undefined; }
  if (Array.isArray(result)) return result[0];
  if (result && Array.isArray(result.documents)) return result.documents[0];
  return undefined;
}

function wifToPrivate(wif) {
  return Buffer.from(PrivateKey.fromWIF(wif).toBytes());
}

/** Retry a flaky DAPI operation up to 3 times with backoff. */
async function withRetry(fn, label) {
  let lastErr;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      console.warn(`[responder] ${label} attempt ${attempt} failed: ${err?.message ?? err}`);
      if (attempt < 3) await new Promise((r) => setTimeout(r, attempt * 2000));
    }
  }
  throw lastErr;
}

main().catch((err) => {
  console.error('[responder] FAILED:', err?.message ?? err?.toString?.() ?? err);
  if (err?.code) console.error('  code:', err.code);
  if (err?.details) console.error('  details:', JSON.stringify(err.details, null, 2));
  if (err?.cause) console.error('  cause:', err.cause?.message ?? err.cause);
  process.exit(1);
});
