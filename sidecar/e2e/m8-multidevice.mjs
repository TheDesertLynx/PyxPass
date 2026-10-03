#!/usr/bin/env node
//
// M8 — multi-machine (two-device) sync test on testnet.
//
// Device A and Device B are independent OS processes (`pyxpass-cli.mjs`), each
// a fresh SyncSession = one logical device/machine sharing one on-chain vault.
// Proves, against the live testnet:
//   1. a second device sees an entry created by the first,
//   2. concurrent edit-vs-edit resolves last-writer-wins by LOGICAL edit time,
//      in BOTH directions, with no data loss,
//   3. edit-vs-delete resolves remote-delete wins (no resurrection).
//
// Non-stale operations use the deterministic one-shot CLI mode (a process per
// device). A "stale" device is held open in the REPL: it pulls the old base,
// another device pushes, then the stale device pushes its own edit -> LWW.
//
// Run: `node e2e/m8-multidevice.mjs` (needs funded identity + PLATFORM_MNEMONIC)
//
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PW = process.env.M8_PASSWORD || 'pyxpass-m8-test-password';
const CLI = fileURLToPath(new URL('../pyxpass-cli.mjs', import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
const check = async (name, fn) => {
  try {
    await fn();
    console.log(`  \u2713 ${name}`);
  } catch (e) {
    failures++;
    console.log(`  \u2717 ${name} \u2014 ${e.message}`);
  }
};

/** One-shot CLI: spawn node pyxpass-cli.mjs <args...>, resolve on exit. */
function oneShot(args) {
  return new Promise((resolve) => {
    const p = spawn('node', [CLI, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    p.stdout.setEncoding('utf8');
    p.stdout.on('data', (d) => (out += d));
    p.on('exit', () => resolve(out));
  });
}
// Strip the env-injection banner and the trailing "error:" noise helpers.
const clean = (s) =>
  s
    .split('\n')
    .filter((l) => !/injected env|^◇/.test(l) && l.trim() !== '')
    .join('\n');

/** A CLI REPL process (held open) acting as one logical "device". */
class Device {
  constructor(name) {
    this.name = name;
    this.buffer = '';
    this.proc = spawn('node', [CLI], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.proc.stdin.on('error', () => {});
    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (d) => (this.buffer += d));
    this.prompt = this.waitPrompt();
  }
  /** Resolve on the next "pyxpass> " prompt. */
  waitPrompt() {
    return new Promise((resolve) => {
      const onData = (d) => {
        if (d.toString().includes('pyxpass> ')) {
          this.proc.stdout.removeListener('data', onData);
          resolve();
        }
      };
      this.proc.stdout.on('data', onData);
      // Safety: resolve after a generous 30s even if the prompt is missed.
      setTimeout(resolve, 30000);
    });
  }
  async ready() {
    await this.prompt;
    await sleep(500);
  }
  /** Send a line, wait for its output (prompt + generous settle). */
  async cmd(line) {
    this.proc.stdin.write(line + '\n');
    await this.waitPrompt();
    await sleep(2500); // let the command's stdout fully land in the buffer
  }
  drain() {
    const s = this.buffer;
    this.buffer = '';
    return clean(s);
  }
  async close() {
    this.proc.stdin.write('exit\n');
    await sleep(500);
    this.proc.kill();
  }
}

let entryId;

// ---------------------------------------------------------------------------
// 1. Device A creates an entry; Device B (fresh process) sees it.
// ---------------------------------------------------------------------------
console.log('\n[1] cross-device visibility');
await check('device A creates entry', async () => {
  const out = await oneShot(['create', PW, 'm8-entry', 'a-secret']);
  const m = out.match(/Created (\S+)/);
  if (!m) throw new Error('create did not report an id: ' + out);
  entryId = m[1];
});

await check('device B (fresh process) sees A\u2019s entry', async () => {
  const out = await oneShot(['list', PW]);
  if (!out.includes(entryId)) throw new Error('entry not visible on B:\n' + out);
});

// ---------------------------------------------------------------------------
// 2. Concurrent edit-vs-edit, LWW. B holds a STALE base (pulled before A
//    pushed). B's edit time is LATER than A's -> B wins.
// ---------------------------------------------------------------------------
console.log('\n[2] concurrent edit-vs-edit (later edit wins)');
let B;
await check('device B holds a stale base (unlock, no save)', async () => {
  B = new Device('B');
  await B.ready();
  await B.cmd(`unlock ${PW}`);
});

await check('device A pushes a conflicting edit first', async () => {
  const out = await oneShot(['edit', PW, entryId, 'A-concurrent', 'a2']);
  if (!/Pushed 1 entry/.test(out)) throw new Error('A did not push: ' + out);
});

await check('device B pushes its stale edit -> LWW (B later, B wins)', async () => {
  await B.cmd(`edit ${entryId} B-concurrent b2`); // marks dirty (REPL)
  await B.cmd(`save`); // pushes
  const out = B.drain();
  if (!/Pushed 1 entry/.test(out)) throw new Error('B expected no conflict, got:\n' + out);
});

await check('chain now holds B\u2019s value (no data loss, entry intact)', async () => {
  const out = await oneShot(['show', PW, entryId]);
  if (!out.includes('B-concurrent')) throw new Error('expected B-concurrent on chain:\n' + out);
});
await B.close();

// ---------------------------------------------------------------------------
// 3. Reverse direction: B edits EARLIER than A, so B LOSES (remote wins) even
//    though B started first.
// ---------------------------------------------------------------------------
console.log('\n[3] concurrent edit-vs-edit (earlier edit loses)');
await check('device B edits first and holds (early logical time)', async () => {
  B = new Device('B');
  await B.ready();
  await B.cmd(`unlock ${PW}`);
  await B.cmd(`edit ${entryId} B-early e1`); // local edit time tB (early), unsaved
});

await check('device A pulls the same base, edits LATER, and pushes', async () => {
  const out = await oneShot(['edit', PW, entryId, 'A-late', 'a3']);
  if (!/Pushed 1 entry/.test(out)) throw new Error('A did not push: ' + out);
});

await check('device B saves its early edit -> conflict, remote wins', async () => {
  await B.cmd(`save`);
  const out = B.drain();
  if (!/resolved remote/.test(out)) throw new Error('expected remote conflict:\n' + out);
});

await check('chain now holds A\u2019s (later) value; B dropped, no corruption', async () => {
  const out = await oneShot(['show', PW, entryId]);
  if (!out.includes('A-late')) throw new Error('expected A-late on chain:\n' + out);
});
await B.close();

// ---------------------------------------------------------------------------
// 4. Edit-vs-delete: B holds a stale edit; A deletes on-chain. B's save must
//    resolve remote-delete (no resurrection).
// ---------------------------------------------------------------------------
console.log('\n[4] edit-vs-delete (remote-delete wins)');
await check('device B holds a stale edit', async () => {
  B = new Device('B');
  await B.ready();
  await B.cmd(`unlock ${PW}`);
  await B.cmd(`edit ${entryId} ghost x`);
});

await check('device A deletes the entry on-chain', async () => {
  const out = await oneShot(['delete', PW, entryId]);
  if (!out.includes(`Deleted ${entryId}`)) throw new Error('delete failed:\n' + out);
});

await check('device B saves stale edit -> resolved remote-deleted', async () => {
  await B.cmd(`save`);
  const out = B.drain();
  if (!/resolved remote-deleted/.test(out)) throw new Error('expected remote-deleted:\n' + out);
});

await check('entry is gone everywhere (no resurrection, no data loss)', async () => {
  const out = await oneShot(['list', PW]);
  if (out.includes(entryId)) throw new Error('entry resurrected:\n' + out);
});
await B.close();

console.log(`\nM8 ${failures === 0 ? 'PASS' : 'FAIL'} (${failures} failure${failures === 1 ? '' : 's'})`);
process.exit(failures === 0 ? 0 : 1);
