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

## Protocol
- After every milestone: update TASKS.md (mark done), write 5-line summary here, git commit + push.
- Blocked >15 min: write options + recommended default here, pick default, continue.
- If context lost: read this file + TASKS.md to resume.
- Verify each milestone's ACCEPT criteria before moving on.
