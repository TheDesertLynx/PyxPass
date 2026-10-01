# PyxPass — Task Tracker

PyxPass is a fork of KeePassXC that stores password entries as encrypted per-entry
documents on Dash Platform. Platform is the SOLE source of truth — no local `.kdbx`.

Milestones must be completed in order. ACCEPT criteria must be verified before moving on.

## MILESTONE 1 — Repo hygiene ✅
- [x] Create this TASKS.md and NOTES.md in the repo
- [x] Set up testnet config constants in one file (dapi endpoints, faucet, contract id placeholder)
- [x] Clean commit + push
- ACCEPT: repo has TASKS.md/NOTES.md, clean commit — DONE (commit e218ab67)

## MILESTONE 2 — Node sidecar scaffold ✅
- [x] npm init, install @dashevo/evo-sdk
- [x] Create sidecar/ dir with index.js (JSON-RPC server skeleton)
- [x] Wire testnet connection per the Dash "Setup SDK Client" tutorial
- ACCEPT: sidecar starts, connects to testnet DAPI — DONE (commit d8cd48bc). Fetch-an-identity awaits M3 (no identity exists yet).

## MILESTONE 3 — Testnet identity + contract ✅
- [x] Create a testnet identity (fund from testnet faucet)
- [x] Register the PyxPass data contract (entry + meta doc types)
- [x] Verify both on-chain via SDK fetch (identity + contract retrievable)
- [x] Store identity/contract ids in config (NOT git-committed keys)
- ACCEPT: contract on testnet; identity has credit balance — DONE (commit b30327fd)
- Identity: 5dNzK6FTWkBXyvwRvG2awxcbi3LmJaHCyGiyas7MXJtf (bal ~14.9B)
- Contract: 2LymHNVi4qF7emJLcqgcVoNiS8MycsaRFVc5iM2cNaFL (block 609497)

## MILESTONE 4 — Crypto module (standalone, fully unit-tested) ✅
- [x] Implement KDF (Argon2id) + HKDF-SHA256 + AES-256-GCM per spec
- [x] Unit tests: encrypt->decrypt round-trip, wrong-password fails, IV uniqueness, rotation changes encKey
- ACCEPT: all crypto unit tests pass — DONE (commit ba6247d3, `npm test` 6/6 green)

## MILESTONE 5 — Sidecar document CRUD
- [ ] meta doc read/write
- [ ] entry doc create/replace/delete/fetch via evo-sdk
- [ ] One transition at a time (batch limit = 1); handle nonces + signing + fee top-up
- ACCEPT: end-to-end create/fetch/update/delete of an encrypted entry on testnet, verified in explorer

## MILESTONE 6 — Sync logic + CLI test harness
- [ ] Full pull on unlock, per-entry diff push on save, last-writer-wins by $updatedAt, conflict detection
- [ ] Standalone CLI test harness (no KeePassXC needed)
- ACCEPT: CLI can unlock, list, create, edit, delete; second identity/device sees updates; conflicts resolve LWW

## MILESTONE 7 — KeePassXC fork wiring
- [ ] Add "Open from Platform" and "Save to Platform" actions
- [ ] On unlock, call sidecar.unlock, hydrate the in-memory Database
- [ ] Hook entry CRUD to sidecar methods
- [ ] Do NOT write any .kdbx file; .kdbx import only as optional seed path
- ACCEPT: fork opens a vault from Platform, edits entries, and changes persist

## MILESTONE 8 — Multi-machine test
- [ ] Two sidecar instances (different testnet identities or same identity) edit entries
- [ ] Verify last-writer-wins and no data loss
- ACCEPT: multi-machine sync works without data loss

## GUARDRAILS (hard rules — never violate)
- TESTNET ONLY. No mainnet spending unless explicitly told.
- Never enable on-chain history (documentsKeepHistory must stay false).
- Never store plaintext passwords on Platform.
- Never commit keys, seeds, or master passwords to git. Use .gitignore + env vars.
- Never embed the Dash SDK in the C++ fork. Sidecar only.
- No local KDBX writes. Platform is the only persistence.
- Every entry operation is its own signed state transition (batch limit = 1).
