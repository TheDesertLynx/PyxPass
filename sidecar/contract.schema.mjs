#!/usr/bin/env node
//
// PyxPass data-contract schema (Milestone 3).
//
// Two document types:
//   meta  — one vault-metadata doc (master-key salt, crypto version, rotation)
//   entry — one doc per password entry (encrypted AES-256-GCM blob)
//
// Design notes (locked in the spec):
//   - Crypto: Argon2id master key + HKDF per-entry keys + AES-256-GCM.
//   - Plaintext never stored on Platform — only ciphertext + IV + metadata.
//   - History disabled (documentsKeepHistory=false) — never enable on-chain history.
//   - Each property must carry a `position` (Platform >= v0.25.16).
//   - maxItems sized to the spec's 5,120-byte max field limit.
//
// v1 schema — may gain fields during M4/M5 crypto + sync work, but the
// registered contract must not change the meaning of existing fields.
//
export const contractSchema = {
  meta: {
    type: 'object',
    properties: {
      version: { type: 'integer', minimum: 1, position: 0 },
      salt: { type: 'array', byteArray: true, maxItems: 32, position: 1 },
      rotation: { type: 'integer', minimum: 0, position: 2 },
      updatedAt: { type: 'integer', position: 3 },
    },
    required: ['version', 'salt', 'rotation'],
    additionalProperties: false,
  },
  entry: {
    type: 'object',
    indices: [
      {
        name: 'ownerId',
        properties: [{ $ownerId: 'asc' }],
        unique: false,
      },
    ],
    properties: {
      encrypted: { type: 'array', byteArray: true, maxItems: 5120, position: 0 },
      iv: { type: 'array', byteArray: true, maxItems: 32, position: 1 },
      version: { type: 'integer', minimum: 1, position: 2 },
      updatedAt: { type: 'integer', position: 3 },
    },
    required: ['encrypted', 'iv', 'version'],
    additionalProperties: false,
  },
};

export default contractSchema;
