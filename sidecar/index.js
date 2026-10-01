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
import { setupDashClient } from './setupDashClient.mjs';

const HOST = process.env.PYXPASS_HOST || '127.0.0.1';
const PORT = Number(process.env.PYXPASS_PORT || 8765);

let sdk = null;
let keyManager = null;
let addressKeyManager = null;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

async function connect() {
  if (sdk) return;
  const res = await setupDashClient({ requireIdentity: false });
  sdk = res.sdk;
  keyManager = res.keyManager; // createForNewIdentity (no on-chain id yet)
  addressKeyManager = res.addressKeyManager;
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

  // ---- stubs for later milestones (M4 crypto, M5 CRUD) ----
  async unlock() {
    throw new Error('unlock: not implemented until Milestone 4 (crypto)');
  },
  async lock() {
    throw new Error('lock: not implemented until Milestone 4 (crypto)');
  },
  async getMeta() {
    throw new Error('getMeta: not implemented until Milestone 5 (meta doc CRUD)');
  },
  async createEntry() {
    throw new Error('createEntry: not implemented until Milestone 5 (entry CRUD)');
  },
  async updateEntry() {
    throw new Error('updateEntry: not implemented until Milestone 5 (entry CRUD)');
  },
  async deleteEntry() {
    throw new Error('deleteEntry: not implemented until Milestone 5 (entry CRUD)');
  },
  async listEntries() {
    throw new Error('listEntries: not implemented until Milestone 6 (sync)');
  },
  async rotateKeys() {
    throw new Error('rotateKeys: not implemented until Milestone 5 (meta CRUD)');
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
