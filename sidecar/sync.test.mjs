#!/usr/bin/env node
//
// Milestone 6 — two-device sync + LWW conflict test on testnet.
//
// Device A and Device B are independent SyncSession instances sharing one
// on-chain vault (same identity, same meta). Proves:
//   1. second device sees updates (B pulls what A created),
//   2. edit-vs-edit conflict resolves LWW (newest $updatedAt wins),
//   3. edit-vs-delete conflict resolves remote-delete wins.
//
// Run: `node sync.test.mjs` (needs funded identity + PLATFORM_MNEMONIC)
//
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setupDashClient } from './setupDashClient.mjs';
import { PyxVault } from './vault.mjs';
import { SyncSession } from './sync.mjs';

const CONTRACT = '2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL';
const PASSWORD = 'pyxpass-m6-test-password';
const enc = (o) => Buffer.from(JSON.stringify(o));
const titleOf = (b) => JSON.parse(Buffer.from(b).toString('utf8')).title;

const cfg = JSON.parse(
  await readFile(new URL('../config/testnet.json', import.meta.url), 'utf8'),
);

const { sdk, keyManager } = await setupDashClient();
const newVault = () =>
  new PyxVault({
    sdk,
    keyManager,
    contractId: CONTRACT,
    metaId: cfg.vault?.metaId ?? null,
  });

let failures = 0;
const check = async (name, fn) => {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failures++;
    console.log(`  ✗ ${name} — ${e.message}`);
  }
};

// ---- Device A creates an entry; Device B (fresh session) sees it ----
const A = new SyncSession({ vault: newVault() });
const B = new SyncSession({ vault: newVault() });

let entryId;
const C = Date.now(); // creation-time base for deterministic LWW timestamps
await check('device A unlock + create entry', async () => {
  await A.unlock(PASSWORD);
  entryId = await A.createEntry(enc({ title: 'shared', secret: 'a-secret' }));
});

await check('device B unlock sees A\u2019s entry (second device)', async () => {
  await B.unlock(PASSWORD);
  const list = B.listEntries();
  assert.ok(list.some((e) => e.entryId === entryId), 'entry not visible on B');
  const pt = await B.getEntry(entryId);
  assert.equal(titleOf(pt), 'shared');
});

// ---- LWW edit-vs-edit conflict: A edits at T1, B edits at T2 (>T1), B pushes first ----
const T1 = C + 1000;
const T2 = C + 2000; // B is strictly later
await check('A edits locally (T1), B edits locally (T2)', async () => {
  A.editLocal(entryId, enc({ title: 'shared-A', secret: 'a2' }), T1);
  B.editLocal(entryId, enc({ title: 'shared-B', secret: 'b2' }), T2);
  assert.equal(A.dirtyCount, 1);
  assert.equal(B.dirtyCount, 1);
});

await check('B pushes first (no conflict, local wins)', async () => {
  const bSave = await B.save();
  assert.deepEqual(bSave.conflicts, []);
  assert.deepEqual(bSave.pushed, [entryId]);
});

await check('A pushes second -> conflict resolved remote (LWW)', async () => {
  const aSave = await A.save();
  const conflict = aSave.conflicts.find((c) => c.entryId === entryId);
  assert.ok(conflict, 'expected a conflict on A');
  assert.equal(conflict.resolved, 'remote');
  // A's local edit was dropped; A now holds B's (newer) value
  const pt = await A.getEntry(entryId);
  assert.equal(titleOf(pt), 'shared-B');
});

await check('final on-chain value is B\u2019s (newest $updatedAt)', async () => {
  await B.pull(); // refresh B's view from chain
  const pt = await B.getEntry(entryId);
  assert.equal(titleOf(pt), 'shared-B');
});

// ---- edit-vs-delete conflict: C deletes on-chain, D has a stale unsaved edit ----
const Cdev = new SyncSession({ vault: newVault() });
const D = new SyncSession({ vault: newVault() });
await Cdev.unlock(PASSWORD);
await D.unlock(PASSWORD); // both have the entry in local state
await check('edit-vs-delete -> remote-delete wins (LWW)', async () => {
  D.editLocal(entryId, enc({ title: 'ghost', secret: 'x' }), T2 + 1000); // stale edit, unsaved
  await Cdev.deleteEntry(entryId); // C deletes on-chain first
  const save = await D.save(); // D tries to push its stale edit
  const conflict = save.conflicts.find((c) => c.entryId === entryId);
  assert.ok(conflict, 'expected a delete conflict');
  assert.equal(conflict.resolved, 'remote-deleted');
  assert.equal(D.dirtyCount, 0);
  assert.ok(!D.listEntries().some((e) => e.entryId === entryId));
});

// ---- cleanup: entry already deleted by C; confirm gone on A ----
await check('cleanup confirms entry deleted everywhere', async () => {
  await A.pull();
  assert.ok(!A.listEntries().some((e) => e.entryId === entryId));
});

for (const s of [A, B, Cdev, D]) s.lock();
await sdk.disconnect?.().catch(() => {});

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);
