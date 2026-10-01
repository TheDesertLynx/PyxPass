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

## Protocol
- After every milestone: update TASKS.md (mark done), write 5-line summary here, git commit + push.
- Blocked >15 min: write options + recommended default here, pick default, continue.
- If context lost: read this file + TASKS.md to resume.
- Verify each milestone's ACCEPT criteria before moving on.
