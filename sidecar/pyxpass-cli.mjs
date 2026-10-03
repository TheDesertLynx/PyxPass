#!/usr/bin/env node
//
// PyxPass standalone CLI harness (Milestone 6) — no KeePassXC needed.
//
// Talks to Dash Platform directly through a fresh SyncSession per invocation,
// so two CLI processes are two logical "devices" sharing one vault. This is
// how a second device sees updates and how LWW conflicts resolve.
//
// Interactive REPL (default):
//   > unlock <password>              full pull into memory
//   > list                           show entries (ids + titles)
//   > show <entryId>                 show one entry (plaintext)
//   > create <title> <secret>        create + push
//   > edit <entryId> <title> <secret>  edit in memory (dirty, NOT pushed)
//   > save                           push all dirty entries (LWW)
//   > delete <entryId>               push delete
//   > pull                           refresh from chain (drops local edits)
//   > lock / exit
//
// One-shot (for scripting): `node pyxpass-cli.mjs <command> [args...]`
//   unlock <pw> | list <pw> | show <pw> <entryId> |
//   create <pw> <title> <secret> | edit <pw> <entryId> <title> <secret> |
//   save <pw> | delete <pw> <entryId> | pull <pw> | lock
//
import { createInterface } from 'node:readline';
import { setupDashClient } from './setupDashClient.mjs';
import { PyxVault } from './vault.mjs';
import { SyncSession } from './sync.mjs';
import { readFile } from 'node:fs/promises';

const CONTRACT = '2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL';

async function openSession() {
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
  const session = new SyncSession({ vault });
  return { session, sdk };
}

const enc = (o) => Buffer.from(JSON.stringify(o));
const dec = (b) => {
  try {
    return JSON.parse(Buffer.from(b).toString('utf8'));
  } catch {
    return { raw: Buffer.from(b).toString('utf8') };
  }
};

async function cmdUnlock(session, pw) {
  const res = await session.unlock(pw);
  console.log(`Unlocked. ${res.entries.length} entries pulled.`);
  return res.entries;
}

function cmdList(session) {
  const list = session.listEntries();
  if (list.length === 0) {
    console.log('(no entries)');
    return;
  }
  for (const e of list) {
    const obj = session.entries.get(e.entryId);
    const title = obj ? dec(obj.plaintext).title || '(untitled)' : '?';
    console.log(`${e.entryId}  ${title}  [${new Date(e.updatedAt).toISOString()}]`);
  }
}

async function cmdShow(session, entryId) {
  const pt = await session.getEntry(entryId);
  if (pt === null) {
    console.log(`entry ${entryId} not found`);
    return;
  }
  console.log(JSON.stringify(dec(pt), null, 2));
}

async function cmdCreate(session, title, secret) {
  const entryId = await session.createEntry(enc({ title, secret }));
  console.log(`Created ${entryId}`);
  return entryId;
}

async function cmdEdit(session, entryId, title, secret) {
  session.editLocal(entryId, enc({ title, secret }));
  console.log(`Edited in memory (dirty). Run "save" to push.`);
}

async function cmdSave(session) {
  const { pushed, conflicts } = await session.save();
  console.log(`Pushed ${pushed.length} entry(s).`);
  for (const c of conflicts) {
    const detail = c.resolved === 'remote-deleted'
      ? 'entry was deleted on another device; local edit dropped'
      : 'remote version is newer; local edit dropped (LWW)';
    console.log(`  conflict on ${c.entryId}: resolved ${c.resolved} — ${detail}`);
  }
}

async function cmdDelete(session, entryId) {
  await session.deleteEntry(entryId);
  console.log(`Deleted ${entryId}`);
}

async function cmdPull(session) {
  const entries = await session.pull();
  console.log(`Pulled ${entries.length} entries (local edits dropped).`);
}

// ---------------------------------------------------------------------------
// Interactive REPL
// ---------------------------------------------------------------------------
async function repl() {
  const { session, sdk } = await openSession();
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const prompt = 'pyxpass> ';

  const handle = async (line) => {
    const [cmd, ...rest] = line.trim().split(/\s+/);
    const [a, b, c] = rest;
    try {
      switch (cmd) {
        case 'unlock': await cmdUnlock(session, a); break;
        case 'list': cmdList(session); break;
        case 'show': await cmdShow(session, a); break;
        case 'create': await cmdCreate(session, a, b); break;
        case 'edit': await cmdEdit(session, a, b, c); break;
        case 'save': await cmdSave(session); break;
        case 'delete': await cmdDelete(session, a); break;
        case 'pull': await cmdPull(session); break;
        case 'lock': session.lock(); console.log('Locked.'); break;
        case 'exit':
        case 'quit': session.lock(); rl.close(); await sdk.disconnect?.().catch(() => {}); return;
        case 'help':
        default:
          console.log('unlock|list|show <id>|create <title> <secret>|edit <id> <title> <secret>|save|delete <id>|pull|lock|exit');
      }
    } catch (e) {
      console.log(`error: ${e.message}`);
    }
    rl.prompt();
  };

  console.log('PyxPass CLI (testnet). Type "help" or "exit".');
  rl.prompt();
  rl.on('line', handle);
}

// ---------------------------------------------------------------------------
// One-shot subcommand mode
// ---------------------------------------------------------------------------
async function oneShot(argv) {
  const [cmd, ...args] = argv;
  const { session, sdk } = await openSession();
  try {
    switch (cmd) {
      case 'unlock': { const pw = args[0]; const res = await cmdUnlock(session, pw); cmdList(session); break; }
      case 'list': { await session.unlock(args[0]); cmdList(session); break; }
      case 'show': { await session.unlock(args[0]); await cmdShow(session, args[1]); break; }
      case 'create': { await session.unlock(args[0]); await cmdCreate(session, args[1], args[2]); break; }
      case 'edit': { await session.unlock(args[0]); await cmdEdit(session, args[1], args[2], args[3]); await cmdSave(session); break; }
      case 'save': { await session.unlock(args[0]); await cmdSave(session); break; }
      case 'delete': { await session.unlock(args[0]); await cmdDelete(session, args[1]); break; }
      case 'pull': { await session.unlock(args[0]); await cmdPull(session); break; }
      case 'lock': break;
      default: console.log('unknown command:', cmd); process.exitCode = 2;
    }
  } catch (e) {
    console.log(`error: ${e.message}`);
    process.exitCode = 1;
  } finally {
    session.lock();
    await sdk.disconnect?.().catch(() => {});
  }
}

const args = process.argv.slice(2);
if (args.length === 0) {
  await repl();
} else {
  await oneShot(args);
}
