//
// PyxPass sync layer (Milestone 6) — session state + LWW conflict resolution.
//
// A SyncSession is the unlocked working copy a device edits. It mirrors the
// KeePassXC flow: unlock -> full pull into memory; user edits entries in
// memory; save pushes only the locally-dirty (changed) entries as a per-entry
// diff. Conflicts resolve last-writer-wins by each entry's on-chain $updatedAt.
//
// Conflict rules (LWW):
//   - edit-vs-edit: the entry with the latest $updatedAt wins.
//       chain.updatedAt > local edit time  -> remote wins, local edit dropped
//       local edit time  >= chain.updatedAt -> local wins, pushed
//   - edit-vs-delete: if the doc vanished on-chain, the remote delete wins.
//
import { PyxVault } from './vault.mjs';

export class SyncSession {
  /**
   * @param {{ vault: PyxVault }} deps
   */
  constructor({ vault }) {
    this.vault = vault;
    this.unlocked = false;
    this.password = null;
    this.meta = null;
    // entryId -> { entryId, plaintext (Buffer), localUpdatedAt (ms), dirty (bool) }
    this.entries = new Map();
  }

  _assertUnlocked() {
    if (!this.unlocked) throw new Error('vault is locked');
  }

  /** Unlock: ensure meta, full pull of all entries into memory. */
  async unlock(password) {
    this.password = password;
    this.meta = await this.vault.ensureMeta(password);
    this.unlocked = true;
    await this.pull();
    return { metaId: this.meta.metaId, entries: this.listEntries() };
  }

  lock() {
    this.password = null;
    this.meta = null;
    this.entries.clear();
    this.unlocked = false;
  }

  /** Full pull: refresh in-memory state from chain (overwrites local edits). */
  async pull() {
    this._assertUnlocked();
    const list = await this.vault.listEntries();
    const next = new Map();
    for (const { entryId, updatedAt } of list) {
      const pt = await this.vault.readEntry(entryId, this.password);
      if (pt === null) continue; // raced a delete
      next.set(entryId, {
        entryId,
        plaintext: pt,
        localUpdatedAt: updatedAt,
        dirty: false,
      });
    }
    this.entries = next;
    return this.listEntries();
  }

  listEntries() {
    this._assertUnlocked();
    return [...this.entries.values()].map((e) => ({
      entryId: e.entryId,
      updatedAt: e.localUpdatedAt,
    }));
  }

  /** Decrypted plaintext (Buffer) for an entry, or null. */
  async getEntry(entryId) {
    this._assertUnlocked();
    const e = this.entries.get(entryId);
    return e ? e.plaintext : null;
  }

  /** Create a new entry on-chain and add it to local state. */
  async createEntry(plaintext) {
    this._assertUnlocked();
    const updatedAt = Date.now();
    const entryId = await this.vault.createEntry(this.password, plaintext, updatedAt);
    this.entries.set(entryId, {
      entryId,
      plaintext,
      localUpdatedAt: updatedAt,
      dirty: false,
    });
    return entryId;
  }

  /** Edit an entry in memory only (marks it dirty); does NOT push. */
  editLocal(entryId, plaintext, ts = Date.now()) {
    this._assertUnlocked();
    const cur = this.entries.get(entryId);
    if (!cur) throw new Error(`entry ${entryId} not in local state — pull first`);
    this.entries.set(entryId, {
      entryId,
      plaintext,
      localUpdatedAt: ts,
      dirty: true,
    });
  }

  /**
   * Push every dirty entry as a per-entry diff, resolving conflicts LWW.
   * @returns {{ pushed: string[], conflicts: Array<{entryId: string, resolved: 'remote'|'remote-deleted', plaintext?: Buffer}> }}
   */
  async save() {
    this._assertUnlocked();
    const pushed = [];
    const conflicts = [];
    for (const [entryId, local] of [...this.entries.entries()]) {
      if (!local.dirty) continue;

      const doc = await this.vault.getEntryDoc(entryId);
      if (!doc) {
        // Deleted elsewhere -> remote delete wins (LWW).
        this.entries.delete(entryId);
        conflicts.push({ entryId, resolved: 'remote-deleted' });
        continue;
      }
      const chainUpdatedAt = Number(doc.properties.updatedAt);
      if (chainUpdatedAt > local.localUpdatedAt) {
        // Remote is newer -> remote wins; pull the remote value into local.
        const remotePt = await this.vault.readEntry(entryId, this.password);
        this.entries.set(entryId, {
          entryId,
          plaintext: remotePt ?? local.plaintext,
          localUpdatedAt: chainUpdatedAt,
          dirty: false,
        });
        conflicts.push({ entryId, resolved: 'remote', plaintext: remotePt ?? undefined });
        continue;
      }

      // Local wins -> push (vault.updateEntry bumps revision and re-encrypts).
      // Write the LOGICAL edit time as updatedAt so on-chain LWW compares edits.
      await this.vault.updateEntry(this.password, entryId, local.plaintext, local.localUpdatedAt);
      this.entries.set(entryId, {
        entryId,
        plaintext: local.plaintext,
        localUpdatedAt: local.localUpdatedAt,
        dirty: false,
      });
      pushed.push(entryId);
    }
    return { pushed, conflicts };
  }

  /** Delete an entry on-chain immediately and drop it from local state. */
  async deleteEntry(entryId) {
    this._assertUnlocked();
    await this.vault.deleteEntry(entryId);
    this.entries.delete(entryId);
  }

  /** Count of dirty (unsaved) entries. */
  get dirtyCount() {
    let n = 0;
    for (const e of this.entries.values()) if (e.dirty) n++;
    return n;
  }
}

export default SyncSession;
