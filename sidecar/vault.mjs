//
// PyxPass vault module (Milestone 5) — document CRUD on Dash Platform.
//
// Thin layer over the beta evo-sdk that encodes the proven-on-testnet
// mechanics for the meta singleton and encrypted per-entry documents:
//
//   meta  — one doc per vault: master-key salt, crypto version, rotation.
//           Created once at init; its doc id is stored in config (the salt
//           and version live on-chain — only the pointer is local).
//   entry — one doc per password entry: AES-256-GCM ciphertext + IV.
//           The entryId IS the on-chain document id (SDK-generated at
//           construction), which keeps crypto derivation and on-chain
//           identity in sync across devices.
//
// Proven mechanics (see NOTES.md M5):
//   - create: construct Document with `properties: {}`, read its id,
//             encrypt with that id, THEN assign `doc.properties` (byte arrays
//             as Uint8Array), then create.
//   - read:   `get(contractId, type, id)` may lag a create; retry.
//   - update: fetch doc, reassign `properties`, RE-AFFIRM `doc.id`, bump
//             revision (+1), then replace. (Reassigning properties without
//             re-affirming id makes the platform report "document not found".)
//   - delete: pass `{ id, ownerId, dataContractId, documentTypeName }`.
//
import { Document } from '@dashevo/evo-sdk';
import {
  CRYPTO_VERSION,
  generateSalt,
  encryptEntry,
  decryptEntry,
} from './crypto/crypto.mjs';

const RETRY_TRIES = 12;
const RETRY_DELAY_MS = 1500;

export class PyxVault {
  /**
   * @param {{ sdk: EvoSDK, keyManager: IdentityKeyManager,
   *           contractId: string, metaId?: string|null }} deps
   */
  constructor({ sdk, keyManager, contractId, metaId = null }) {
    this.sdk = sdk;
    this.keyManager = keyManager;
    this.contractId = contractId;
    this.metaId = metaId;
    this._auth = null;
    this._meta = null; // { salt, version, rotation }
  }

  async _getAuth() {
    if (!this._auth) this._auth = await this.keyManager.getAuth();
    return this._auth;
  }

  async _getRetry(type, id, tries = RETRY_TRIES) {
    for (let i = 0; i < tries; i++) {
      const doc = await this.sdk.documents.get(this.contractId, type, id);
      if (doc) return doc;
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
    }
    return undefined;
  }

  /** Create the meta singleton if missing; returns { metaId, salt, version, rotation, created }. */
  async ensureMeta(password) {
    if (!this.metaId) {
      const { identity, identityKey, signer } = await this._getAuth();
      const salt = generateSalt();
      const meta = new Document({
        properties: {
          version: CRYPTO_VERSION,
          salt: new Uint8Array(salt),
          rotation: 0,
          updatedAt: Date.now(),
        },
        documentTypeName: 'meta',
        dataContractId: this.contractId,
        ownerId: identity.id,
      });
      await this.sdk.documents.create({ document: meta, identityKey, signer });
      this.metaId = meta.id.toString();
      this._meta = { salt, version: CRYPTO_VERSION, rotation: 0 };
      return { metaId: this.metaId, ...this._meta, created: true };
    }
    const meta = await this.loadMeta();
    if (!meta) throw new Error(`meta doc ${this.metaId} not found on chain`);
    return { metaId: this.metaId, ...meta, created: false };
  }

  /** Fetch the meta doc and cache { salt, version, rotation }; null if absent. */
  async loadMeta() {
    if (!this.metaId) return null;
    const doc = await this._getRetry('meta', this.metaId);
    if (!doc) return null;
    this._meta = {
      salt: Buffer.from(doc.properties.salt),
      version: Number(doc.properties.version),
      rotation: Number(doc.properties.rotation),
    };
    return this._meta;
  }

  /** Create an entry; returns the on-chain entryId (doc id). */
  async createEntry(password, plaintext) {
    const meta = this._meta ?? (await this.loadMeta());
    if (!meta) throw new Error('vault meta not initialized — run ensureMeta first');
    const { identity, identityKey, signer } = await this._getAuth();
    const entry = new Document({
      properties: {},
      documentTypeName: 'entry',
      dataContractId: this.contractId,
      ownerId: identity.id,
    });
    const entryId = entry.id.toString();
    const { ciphertext, iv } = await encryptEntry(
      password, meta.salt, entryId, meta.rotation, plaintext,
    );
    entry.properties = {
      encrypted: new Uint8Array(ciphertext),
      iv: new Uint8Array(iv),
      version: meta.version,
      updatedAt: Date.now(),
    };
    await this.sdk.documents.create({ document: entry, identityKey, signer });
    return entryId;
  }

  /** Read + decrypt an entry; null if the doc doesn't exist. Throws on wrong password. */
  async readEntry(entryId, password) {
    const meta = this._meta ?? (await this.loadMeta());
    if (!meta) throw new Error('vault meta not initialized — run ensureMeta first');
    const doc = await this._getRetry('entry', entryId);
    if (!doc) return null;
    const payload = Buffer.from(doc.properties.encrypted);
    const iv = Buffer.from(doc.properties.iv);
    return decryptEntry(password, meta.salt, entryId, meta.rotation, payload, iv);
  }

  /** Re-encrypt and replace an existing entry. */
  async updateEntry(password, entryId, plaintext) {
    const meta = this._meta ?? (await this.loadMeta());
    if (!meta) throw new Error('vault meta not initialized — run ensureMeta first');
    const { identityKey, signer } = await this._getAuth();
    const doc = await this._getRetry('entry', entryId);
    if (!doc) throw new Error(`entry ${entryId} not found`);
    const { ciphertext, iv } = await encryptEntry(
      password, meta.salt, entryId, meta.rotation, plaintext,
    );
    doc.properties = {
      encrypted: new Uint8Array(ciphertext),
      iv: new Uint8Array(iv),
      version: meta.version,
      updatedAt: Date.now(),
    };
    doc.id = entryId; // re-affirm the id after reassigning properties
    doc.revision = (doc.revision ?? 0n) + 1n;
    await this.sdk.documents.replace({ document: doc, identityKey, signer });
  }

  /** Delete an entry by id. */
  async deleteEntry(entryId) {
    const { identity, identityKey, signer } = await this._getAuth();
    await this.sdk.documents.delete({
      document: {
        id: entryId,
        ownerId: identity.id,
        dataContractId: this.contractId,
        documentTypeName: 'entry',
      },
      identityKey,
      signer,
    });
  }

  /** List all entries (ids + updatedAt) without decrypting. */
  async listEntries() {
    const { identity } = await this._getAuth();
    const result = await this.sdk.documents.query({
      dataContractId: this.contractId,
      documentTypeName: 'entry',
      where: [['$ownerId', '==', identity.id.toString()]],
      limit: 100,
    });
    const out = [];
    for (const [id, doc] of result) {
      if (doc) out.push({ entryId: id, updatedAt: Number(doc.properties.updatedAt) });
    }
    return out;
  }

  async disconnect() {
    await this.sdk.disconnect?.().catch(() => {});
  }
}

export default PyxVault;
