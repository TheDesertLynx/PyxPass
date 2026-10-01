#!/usr/bin/env node
//
// Milestone 5 — end-to-end CRUD test for the PyxVault module on testnet.
//
// Exercises: meta init, entry create/read/update/delete, list, wrong-password.
// Run: `node vault.test.mjs`  (needs PLATFORM_MNEMONIC + funded identity)
//
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setupDashClient } from './setupDashClient.mjs';
import { PyxVault } from './vault.mjs';

const CONTRACT = '2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL';
const PASSWORD = 'pyxpass-m5-test-password';
const enc = (o) => Buffer.from(JSON.stringify(o));

// Load persisted vault metaId (created by the first init run)
const cfg = JSON.parse(
  await readFile(new URL('../config/testnet.json', import.meta.url), 'utf8'),
);

const { sdk, keyManager } = await setupDashClient();
const vault = new PyxVault({
  sdk,
  keyManager,
  contractId: CONTRACT,
  metaId: cfg.vault?.metaId ?? null,
});

let failures = 0;
const check = async (name, fn) => {
  try {
    return await fn();
  } catch (e) {
    failures++;
    console.log(`  ✗ ${name} — ${e.message}`);
    return undefined;
  }
};

// ---- META ----
const meta1 = await check('init vault meta (reuses persisted id)', async () => {
  const m = await vault.ensureMeta(PASSWORD);
  assert.equal(typeof m.metaId, 'string');
  assert.equal(m.version, 1);
  assert.equal(m.rotation, 0);
  assert.equal(m.metaId, cfg.vault?.metaId);
  assert.equal(vault.metaId, m.metaId);
});
console.log('    metaId:', vault.metaId);

const meta2 = await check('loadMeta returns cached salt', async () => {
  const m = await vault.loadMeta();
  assert.ok(m.salt.length > 0);
  assert.equal(m.version, 1);
});

// ---- ENTRY CREATE/READ ----
const entryId = await check('create entry', async () => {
  const id = await vault.createEntry(PASSWORD, enc({ title: 'Dash seed', secret: 's3cr3t' }));
  assert.equal(typeof id, 'string');
  return id;
});

await check('read entry round-trip', async () => {
  const pt = await vault.readEntry(entryId, PASSWORD);
  const obj = JSON.parse(pt.toString('utf8'));
  assert.equal(obj.title, 'Dash seed');
  assert.equal(obj.secret, 's3cr3t');
});

await check('wrong password fails', async () => {
  await assert.rejects(() => vault.readEntry(entryId, 'wrong-password'), /auth tag|unable|decrypt|Unsupported|error/i);
});

// ---- ENTRY UPDATE ----
await check('update entry (replace)', async () => {
  await vault.updateEntry(PASSWORD, entryId, enc({ title: 'Dash seed UPDATED', secret: 'changed' }));
});

await check('read updated entry', async () => {
  const pt = await vault.readEntry(entryId, PASSWORD);
  const obj = JSON.parse(pt.toString('utf8'));
  assert.equal(obj.title, 'Dash seed UPDATED');
  assert.equal(obj.secret, 'changed');
});

// ---- LIST ----
await check('list includes entry', async () => {
  const list = await vault.listEntries();
  assert.ok(list.some((e) => e.entryId === entryId), `entryId ${entryId} not in list`);
});

// ---- DELETE ----
await check('delete entry', async () => {
  if (entryId) await vault.deleteEntry(entryId);
});

await check('entry gone after delete', async () => {
  await new Promise((r) => setTimeout(r, 3000));
  const pt = await vault.readEntry(entryId, PASSWORD);
  assert.equal(pt, null);
});

await vault.disconnect();

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);
