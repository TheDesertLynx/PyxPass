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

## MILESTONE 5 — Sidecar document CRUD ✅
- [x] meta doc read/write
- [x] entry doc create/replace/delete/fetch via evo-sdk
- [x] One transition at a time (batch limit = 1); handle nonces + signing + fee top-up
- ACCEPT: end-to-end create/fetch/update/delete of an encrypted entry on testnet, verified in explorer — DONE (`vault.mjs` + `vault.test.mjs`, `npm run test:m5` ALL PASS)
- meta doc on-chain: 2p8ZyaDEyd3j3noWuDpwuywzh93jBHWxkGjvpvgC2RrQ (version 1, rotation 0, 16-byte salt)

## MILESTONE 6 — Sync logic + CLI test harness ✅
- [x] Full pull on unlock, per-entry diff push on save, last-writer-wins by $updatedAt, conflict detection
- [x] Standalone CLI test harness (no KeePassXC needed)
- ACCEPT: CLI can unlock, list, create, edit, delete; second identity/device sees updates; conflicts resolve LWW — DONE (`sync.mjs`, `pyxpass-cli.mjs`, `sync.test.mjs`, RPC wired in `index.js`)
- `npm run test:m6` ALL PASS: second device sees updates; edit-vs-edit resolves LWW; edit-vs-delete remote-delete wins

## MILESTONE 7 — KeePassXC fork wiring
- [ ] M7a: Build toolchain — get the fork compiling (Qt6 + Botan + zlib/minizip + pcsc/libusb) without sudo
- [ ] M7b: PyxPass sidecar HTTP client (C++): JSON-RPC over HTTP to 127.0.0.1:8765 (unlock/list/create/update/delete/save/lock)
- [ ] M7c: Storage integration — hydrate in-memory Database from sidecar.unlock; persist edits via sidecar.save
- [ ] M7d: GUI actions "Open from Platform" / "Save to Platform"; hook entry CRUD to sidecar methods
- [ ] M7e: No .kdbx writes (.kdbx import only as optional seed path); verify ACCEPT
- ACCEPT: fork opens a vault from Platform, edits entries, and changes persist

## MILESTONE 8 — Multi-machine test
- [ ] M8a: Two sidecar instances / sessions (same identity = two devices) edit entries concurrently
- [ ] M8b: Verify last-writer-wins and no data loss
- ACCEPT: multi-machine sync works without data loss

## GUARDRAILS (hard rules — never violate)
- TESTNET ONLY. No mainnet spending unless explicitly told.
- Never enable on-chain history (documentsKeepHistory must stay false).
- Never store plaintext passwords on Platform.
- Never commit keys, seeds, or master passwords to git. Use .gitignore + env vars.
- Never embed the Dash SDK in the C++ fork. Sidecar only.
- No local KDBX writes. Platform is the only persistence.
- Every entry operation is its own signed state transition (batch limit = 1).

## MILESTONE 9 — DashConnect protocol module ✅ COMPLETE
- [x] M9a: Parse dash-key: URI (0x01 ‖ appEphemeralPub(33) ‖ contractId(32) ‖ labelLen ‖ label), plain base58, ?n=t&v=1
- [x] M9b: ECDH shared secret + AES-GCM login-key envelope decryption; loginKey = HKDF(chainKey, identityId, "dash:login-key:v1" ‖ contractId)
- [x] M9c: loginKeyResponse publish/poll to yappr key-exchange contract 7UaqHGBJBbRLJ4fUWS45cnud8PPUugJWoGTt1SKwHJ2P (protocol draft + SDK create-or-replace adapter; live publish is M10 e2e)
- [x] M9d: First-login registration (dash-st: URI): IdentityUpdate adding auth key (ECDSA_HASH160, AUTHENTICATION/HIGH) + enc key (ECDSA_SECP256K1, ENCRYPTION/MEDIUM) — buildRegistrationKeyData + registerLoginKeys adapter
- ACCEPT ✅: request byte-identical to DashConnectUriTest.kt SERIALIZED_REQUEST_HEX; key derivation matches KeyExchangeCryptoTest.kt vectors — 32/32 unit tests pass (sidecar/dashconnect/protocol.test.mjs)

## MILESTONE 10 — Sidecar DashConnect JSON-RPC + KeePassXC UI
- [x] M10a: sidecar dashconnectInit/dashconnectPoll/dashconnectComplete JSON-RPC methods (commit 57e56e81)
- [ ] M10b: KeePassXC QR/deep-link UI for the dash-key: URI (login via DashConnect option)
- ACCEPT: end-to-end DashConnect login on testnet (scripted responder e2e/wallet-responder.mjs or DashPay wallet) ✅ (M10a verified live 2026-10-02)

## MILESTONE 11 — Security hardening
- [ ] M11a: Confirmation mitigations (full identityId + DPNS name + reg time; warn new <1d / no DPNS; confirm username + start/end of identityId)
- [ ] M11b: RevokedWalletKey refusal — never re-accept a disabled login key
- [ ] M11c: Buffer zeroing after use (ephemeral keys, login keys, derived keys, envelope AES key, decoded privkey bytes)
- [ ] M11d: 5-min request expiry + countdown; QR kept private; deep-link hijack note
- ACCEPT: security review checklist from wallet-login.md fully implemented

## GUARDRAILS (extended — DashConnect)
- DashConnect = ALTERNATIVE entry point; master-password unlock stays PRIMARY.
- TESTNET ONLY — mainnet DashConnect disabled in wallets.
- NEVER accept CRITICAL/MASTER key for login; require AUTHENTICATION/HIGH.
- Verify granted key: on responder identity, not disabled/expired, has budget, private key controlled.
- login key is proof of identity ownership only — does NOT derive vault encryption keys (master password + Argon2 + HKDF unchanged).
- documentsKeepHistory stays false. Never store plaintext. Never commit keys/seeds.
