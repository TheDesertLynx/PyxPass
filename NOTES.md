# PyxPass — Build Notes (source of truth for progress)

## 2026-09-30 — Session start
- PyxPass = KeePassXC fork storing password entries as encrypted per-entry documents on
  Dash Platform. Platform is the SOLE source of truth. No local `.kdbx` canonical file.
- Fork created at github.com/TheDesertLynx/PyxPass. Local clone at ~/pyxpass.
- Remotes: origin = TheDesertLynx/PyxPass, upstream = keepassxreboot/keepassxc. Branch: develop.
- Sidecar: Node.js, @dashevo/evo-sdk. Crypto lives in the sidecar (Node crypto).
- Data contract: two doc types, `entry` and `meta` (see spec). documentsKeepHistory = false.
- Crypto: masterKey = Argon2id(masterPassword, salt); entryKey = HKDF(masterKey, "pyxpass-entry:..."); encKey = HKDF(entryKey, "pyxpass-enc:..."); AES-256-GCM.
- Fees: 1 Dash = 1e11 credits; permanent storage 27,000 cr/byte; write processing 400/byte;
  max ST 20,480 bytes; max field 5,120 bytes; batch limit = 1.
- TODO verify: exact evo-sdk method names against official Dash docs "Submit documents" and
  "Retrieve documents" tutorials — the sketch may differ.
- Contract id / identity id / faucet status: TBD (Milestone 3).

## MILESTONE 1 — DONE
- Created TASKS.md + NOTES.md in repo; set up config/testnet.json with fee/network constants (DAPI + faucet + contract/identity ids as TODO placeholders).
- Added PyxPass secrets block to .gitignore (env, keys, seeds, *.pem, sidecar/keys/).
- Committed e218ab67 and pushed to origin/develop. Branch now tracks origin/develop.
- Git identity: used inline `-c user.name/user.email` (TheDesertLynx) — no global git config touched.
- Set up `gh auth setup-git` so HTTPS pushes authenticate via the existing gh login. Origin stays HTTPS.

## MILESTONE 2 — DONE
- Read the official Dash docs: Setup SDK Client, Submit documents, Retrieve documents tutorials. Verified evo-sdk 4.1.1 API: EvoSDK.testnetTrusted(), IdentityKeyManager.getAuth() -> {identity, identityKey, signer}, sdk.documents.create/query.
- sidecar/ scaffolded: package.json (evo-sdk 4.1.1 + dotenv), setupDashClient-core.mjs + setupDashClient.mjs extracted verbatim from the tutorial, index.js JSON-RPC server (127.0.0.1:8765, POST /rpc).
- .env holds testnet mnemonic (gitignored). dotenv was required — tutorial treats it as optional, sidecar needs it.
- Server verified: ping -> connected:true; status -> primaryAddress tdash1kr26msyth8l7cval4mma250qnl8zr0uyfgm2usr4. identityId null (no identity yet -> M3).
- Stub methods in place for unlock/lock/getMeta/createEntry/updateEntry/deleteEntry/listEntries/rotateKeys (return "not implemented" until M4/M5).

## MILESTONE 3 — IN PROGRESS (blocked on faucet)
- M3 scripts built + pushed (e9499c4b): register-identity.mjs, register-contract.mjs, contract.schema.mjs (entry + meta doc types, byte-array ciphertext fields, ownerId index, history disabled).
- Verified SDK has createIdentity, identities.nonce, contracts.publish.
- BLOCKED: platform address has 0 balance. Funding requires the testnet Core->Platform bridge, which is browser-interactive (bridge.thepasta.org). This box is headless with no Chromium installed (browser-use skill: do not auto-install).
- Platform address: tdash1kr26msyth8l7cval4mma250qnl8zr0uyfgm2usr4
- Funding URL for Joël: https://bridge.thepasta.org/?address=tdash1kr26msyth8l7cval4mma250qnl8zr0uyfgm2usr4
- After funding: run `npm run register:identity` -> set config/testnet.json identity.id, then `npm run register:contract` -> set contract.id.

## MILESTONE 3 — DONE
- Bridge funding landed (~1000 testnet DASH -> 99,983,769,880 credits on platform address).
- Registered identity 5dNzK6FTWkBXyvwRvG2awxcbi3LmJaHCyGiyas7MXJtf (funded 5M at create, then topped up +30B via sdk.addresses.topUpIdentity).
- Contract registration requires ~15B credits (identity had 5M -> top-up needed). topup-identity.mjs added (reusable).
- Registered contract 2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL at block 609497: documentSchemas = {entry: encrypted/iv/version/updatedAt, meta: version/salt/rotation/updatedAt}, ownerId index, history off.
- Verified both on-chain via SDK fetch. Ids saved to config/testnet.json (identity.id + contract.id).

## MILESTONE 4 — DONE
- crypto/crypto.mjs: derivation chain masterKey=Argon2id(password,salt) -> entryKey=HKDF(masterKey,"pyxpass-entry:<id>") -> encKey=HKDF(entryKey,"pyxpass-enc:<rotation>:<id>") -> AES-256-GCM.
- @node-rs/argon2 2.2.1 returns only the PHC-encoded string (no raw option) — decode the base64 hash segment for the 32-byte key.
- Argon2id params: 64 MiB (m=65536), t=2, p=2, output 32 bytes. GCM: 12-byte IV, 16-byte tag appended to ciphertext.
- Salt (16B) lives in the meta doc; rotation is the meta counter that re-derives every encKey (forces re-encryption).
- crypto/crypto.test.mjs: 6 tests (round-trip, wrong-password fails, IV uniqueness, rotation changes encKey, raw primitives, salt/iv randomness). npm test 6/6 pass. Commit ba6247d3.

## MILESTONE 5 — DONE
- vault.mjs = PyxVault class: ensureMeta/loadMeta (meta singleton), createEntry/readEntry/updateEntry/deleteEntry/listEntries (encrypted per-entry docs). entryId IS the on-chain doc id (SDK-generated at construction) so crypto derivation and on-chain identity stay in sync.
- Meta singleton has no ownerId index and no deterministic id (id commits to the SDK-managed identity nonce), so its doc id is stored in config/testnet.json -> vault.metaId. Salt/version/rotation stay on-chain; only the pointer is local.
- Create mechanics: construct Document with `properties: {}`, read id, encrypt with that id, THEN assign `doc.properties` (byte arrays as Uint8Array) — assigning the whole object (not mutating keys) is what serializes. Fetched docs do NOT expose entropy.
- Update/replace mechanics: fetch doc, reassign `properties`, RE-AFFIRM `doc.id`, bump revision (+1). Skipping the id re-affirm makes the platform error "document not found" despite the doc existing. Fetched `get()` may lag a create — retry loop.
- SDK upgraded 4.1.1 -> 4.2.0-beta.7 (fixes "not an array of bytes" serialization bug). Identity ~14.9B credits covers M5 fees (no top-up needed yet).
- vault.test.mjs (`npm run test:m5`) ALL PASS: meta init/reuse, create/read round-trip, wrong-password fails, update (replace) persists, list by ownerId, delete, gone-after-delete. Meta on-chain: 2p8ZyaDEyd3j3noWuDpwuywzh93jBHWxkGjvpvgC2RrQ.

## MILESTONE 6 — DONE
- sync.mjs = SyncSession: unlock does a FULL pull into an in-memory working copy; editLocal marks an entry dirty; save() pushes ONLY dirty entries (per-entry diff). Conflict LWW by on-chain $updatedAt.
- KEY INSIGHT: on-chain updatedAt must be the LOGICAL edit time, not the push time — vault.createEntry/updateEntry now take an explicit updatedAt param; SyncSession writes local.localUpdatedAt on push. Otherwise LWW compares push-times and every second push looks like a conflict.
- LWW rules: chain.updatedAt > local edit -> remote wins (pull remote in, drop local edit); local >= chain -> local wins (push). Doc gone on-chain -> remote-delete wins.
- pyxpass-cli.mjs: standalone CLI (no KeePassXC). Interactive REPL (unlock/list/show/create/edit/save/delete/pull/lock) + one-shot subcommands. Each invocation = a fresh SyncSession = a separate logical device.
- index.js wired to real identity (connect requireIdentity:true) + SyncSession; RPC createEntry/updateEntry serialize JSON plaintext to a Buffer (encBuf). Verified full unlock/create/list/update/delete/lock over JSON-RPC.
- sync.test.mjs (`npm run test:m6`) ALL PASS: two SyncSession instances (devices A/B) share one on-chain vault; B sees A's entry; B's newer edit wins edit-vs-edit; a stale edit vs remote delete resolves remote-deleted.

## Protocol
- After every milestone: update TASKS.md (mark done), write 5-line summary here, git commit + push.
- Blocked >15 min: write options + recommended default here, pick default, continue.
- If context lost: read this file + TASKS.md to resume.
- Verify each milestone's ACCEPT criteria before moving on.
