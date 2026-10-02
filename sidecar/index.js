#!/usr/bin/env node
//
// PyxPass sidecar — JSON-RPC server (Milestone 2 skeleton).
//
// Owns identity keys and all DAPI/gRPC calls via @dashevo/evo-sdk.
// The KeePassXC fork talks to this over localhost JSON-RPC.
//
// Current state: connects to testnet, resolves the mnemonic's identity,
// and exposes stub methods for the crypto/CRUD milestones (M4, M5).
//
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { setupDashClient } from './setupDashClient.mjs';
import { PyxVault } from './vault.mjs';
import { SyncSession } from './sync.mjs';
import { injectPrivateKey, registerLoginKeys } from './dashconnect/protocol.mjs';
import * as dashconnect from './dashconnect/app.mjs';

const HOST = process.env.PYXPASS_HOST || '127.0.0.1';
const PORT = Number(process.env.PYXPASS_PORT || 8765);

let sdk = null;
let keyManager = null;
let addressKeyManager = null;
let config = null;
let session = null; // SyncSession while unlocked
let dashconnectSession = null; // { identityId, authPrivateKey, encPrivateKey } while DashConnect-authenticated

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

async function loadConfig() {
  if (config) return config;
  try {
    config = JSON.parse(
      await readFile(new URL('../config/testnet.json', import.meta.url), 'utf8'),
    );
  } catch {
    config = {};
  }
  return config;
}

async function connect() {
  if (sdk) return;
  const res = await setupDashClient({ requireIdentity: true });
  sdk = res.sdk;
  keyManager = res.keyManager; // resolves the mnemonic's existing identity
  addressKeyManager = res.addressKeyManager;
  injectPrivateKey((await import('@dashevo/evo-sdk')).PrivateKey);
}

async function getVault() {
  await connect();
  const cfg = await loadConfig();
  const contractId = cfg.contract?.id;
  if (!contractId) throw new Error('contract.id missing from config/testnet.json');
  return new PyxVault({
    sdk,
    keyManager,
    contractId,
    metaId: cfg.vault?.metaId ?? null,
  });
}

async function getSession() {
  if (!session) {
    const vault = await getVault();
    session = new SyncSession({ vault });
  }
  return session;
}

/** Serialize JSON plaintext to the Buffer the crypto layer expects. */
function encBuf(plaintext) {
  return Buffer.isBuffer(plaintext)
    ? plaintext
    : Buffer.from(JSON.stringify(plaintext));
}

// ---------------------------------------------------------------------------
// RPC methods
// ---------------------------------------------------------------------------

const methods = {
  /** ping -> { ok, network, connected, identityId } */
  async ping() {
    await connect();
    return {
      ok: true,
      network: 'testnet',
      connected: true,
      identityId: keyManager?.identityId || null,
    };
  },

  /** status -> connection + address balance info */
  async status() {
    await connect();
    const info = addressKeyManager
      ? await addressKeyManager.getInfo().catch(() => null)
      : null;
    return {
      ok: true,
      identityId: keyManager?.identityId || null,
      primaryAddress: addressKeyManager?.primaryAddress?.bech32m || null,
      balance: info?.balance ?? null,
    };
  },

  /** unlock <password> -> full pull; returns metaId + entry list */
  async unlock(password) {
    if (typeof password !== 'string' || !password) {
      throw new Error('unlock requires a password');
    }
    const s = await getSession();
    const res = await s.unlock(password);
    return { ok: true, ...res, identityId: keyManager?.identityId || null };
  },
  /** lock -> clear session state (forget password + entries) */
  async lock() {
    if (session) session.lock();
    session = null;
    // Zero any DashConnect session keys and drop the session (M11c).
    if (dashconnectSession) {
      dashconnect.endSession(dashconnectSession.connectionId);
      dashconnectSession = null;
    }
    return { ok: true };
  },
  /** getMeta -> meta id + crypto version + rotation (no password needed) */
  async getMeta() {
    const cfg = await loadConfig();
    const v = await getVault();
    const meta = await v.loadMeta();
    if (!meta) return { ok: true, exists: false };
    return { ok: true, exists: true, metaId: v.metaId, ...meta };
  },
  /** listEntries -> [{ entryId, updatedAt }] from the unlocked session */
  async listEntries() {
    const s = await getSession();
    return { ok: true, entries: s.listEntries(), dirty: s.dirtyCount };
  },
  /** getEntry <entryId> -> decrypted plaintext (JSON object) for one entry */
  async getEntry(entryId) {
    const s = await getSession();
    const pt = await s.getEntry(entryId);
    if (!pt) return { ok: false, error: `entry not found: ${entryId}` };
    return { ok: true, entryId, entry: JSON.parse(pt.toString('utf8')) };
  },
  /** createEntry <plaintext> -> entryId */
  async createEntry(plaintext) {
    const s = await getSession();
    const entryId = await s.createEntry(encBuf(plaintext));
    return { ok: true, entryId };
  },
  /** updateEntry <entryId> <plaintext> -> edit in memory + save (LWW diff push) */
  async updateEntry(entryId, plaintext) {
    const s = await getSession();
    s.editLocal(entryId, encBuf(plaintext));
    const res = await s.save();
    const mine = res.pushed.includes(entryId);
    const conflicted = res.conflicts.find((c) => c.entryId === entryId);
    return { ok: true, entryId, pushed: mine, conflict: !!conflicted, ...res };
  },
  /** deleteEntry <entryId> -> push delete */
  async deleteEntry(entryId) {
    const s = await getSession();
    await s.deleteEntry(entryId);
    return { ok: true, entryId };
  },
  /** save -> push all locally-dirty entries (per-entry diff, LWW) */
  async save() {
    const s = await getSession();
    return { ok: true, ...(await s.save()) };
  },
  /** pull -> refresh in-memory state from chain */
  async pull() {
    const s = await getSession();
    const entries = await s.pull();
    return { ok: true, entries };
  },
  // -------------------------------------------------------------------------
  // DashConnect (M10a): app-side initiator. Login via a Dash wallet; does NOT
  // unlock the vault. After dashconnectComplete the GUI prompts the master
  // password and calls unlock() normally.
  // -------------------------------------------------------------------------
  /** dashconnectInit <appContractId> [label] -> { connectionId, uri } */
  async dashconnectInit(appContractId, label = null) {
    await connect();
    if (typeof appContractId !== 'string' || !appContractId) {
      throw new Error('dashconnectInit requires appContractId (base58 or hex)');
    }
    const cfg = await loadConfig();
    const contractId = appContractId === 'self'
      ? cfg.contract?.id
      : appContractId;
    if (!contractId) throw new Error('appContractId missing; pass it or configure contract.id');
    return await dashconnect.init({ sdk, appContractIdBytes: contractId, label });
  },
  /** dashconnectPoll <connectionId> -> { status: pending|ready|expired, ... } */
  async dashconnectPoll(connectionId) {
    await connect();
    if (typeof connectionId !== 'string' || !connectionId) {
      throw new Error('dashconnectPoll requires connectionId');
    }
    return await dashconnect.poll({ sdk, connectionId });
  },
  /** dashconnectComplete <connectionId> -> mark session DashConnect-authenticated */
  async dashconnectComplete(connectionId) {
    await connect();
    if (typeof connectionId !== 'string' || !connectionId) {
      throw new Error('dashconnectComplete requires connectionId');
    }
    const res = await dashconnect.complete({ sdk, connectionId });
    // Store derived auth material for the DashConnect-authenticated session.
    // The vault is NOT unlocked; the GUI still prompts the master password.
    // Derived keys stay as Buffers in the sidecar session (zeroable on lock);
    // only identityId + loginKeyHash are exposed over RPC (M11c).
    dashconnectSession = { ...dashconnect.getAuthMaterial(connectionId), connectionId };
    return { ...res, unlocked: false };
  },
  /** dashconnectCancel <connectionId> -> drop a pending request */
  async dashconnectCancel(connectionId) {
    return dashconnect.cancel(connectionId);
  },
  /** dashconnectList -> pending requests for the GUI tray */
  async dashconnectList() {
    return { ok: true, requests: dashconnect.list() };
  },
  /** dashconnectAuth -> current DashConnect-authenticated session info (if any) */
  async dashconnectAuth() {
    if (!dashconnectSession) return { ok: true, authenticated: false };
    return { ok: true, authenticated: true, ...dashconnectSession };
  },
};

// ---------------------------------------------------------------------------
// JSON-RPC transport (POST /rpc, JSON body, one request per connection)
// ---------------------------------------------------------------------------

async function handleRequest(body) {
  const req = JSON.parse(body);
  const { id, method, params } = req;
  const fn = methods[method];
  if (!fn) {
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
  try {
    const result = await fn(...(params || []));
    return { jsonrpc: '2.0', id, result };
  } catch (e) {
    return { jsonrpc: '2.0', id, error: { code: -32000, message: e.message } };
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'POST' && req.url === '/rpc') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      try {
        const reply = await handleRequest(Buffer.concat(chunks).toString('utf8'));
        res.statusCode = 200;
        res.end(JSON.stringify(reply));
      } catch (e) {
        res.statusCode = 400;
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: e.message } }));
      }
    });
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32601, message: 'Use POST /rpc' } }));
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

server.listen(PORT, HOST, () => {
  console.log(`PyxPass sidecar listening on http://${HOST}:${PORT} (testnet)`);
});

server.on('error', (e) => {
  console.error('Server error:', e.message);
  process.exit(1);
});
