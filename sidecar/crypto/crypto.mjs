#!/usr/bin/env node
//
// PyxPass crypto module (Milestone 4).
//
// Derivation chain (locked in the spec):
//   masterKey = Argon2id(masterPassword, salt)
//   entryKey  = HKDF-SHA256(masterKey,  info="pyxpass-entry:<entryId>")
//   encKey    = HKDF-SHA256(entryKey,   info="pyxpass-enc:<rotation>:<entryId>")
//   AES-256-GCM(encKey, plaintext)
//
// Design notes:
//   - The 16-byte salt lives in the `meta` doc (generated once at vault creation).
//   - The 12-byte GCM IV is per-encryption and stored on each `entry` doc.
//   - The 16-byte GCM auth tag is appended to the ciphertext (both in `encrypted`).
//   - `rotation` is the meta-doc counter; bumping it changes every encKey, forcing
//     a full re-encryption of all entries (key rotation).
//   - Plaintext never touches Dash Platform — only ciphertext + IV + metadata.
//
import { hash, Algorithm } from '@node-rs/argon2';
import { hkdfSync, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

/** Crypto version — bump on any breaking change to the derivation. */
export const CRYPTO_VERSION = 1;

/** Argon2id parameters (KeePassXC-flavored: 64 MiB, 2 passes, 2 threads). */
export const ARGON2 = {
  memoryCost: 65536, // KiB = 64 MiB
  timeCost: 2,
  parallelism: 2,
  outputLen: 32, // bytes
};

export const AES_GCM = {
  keyBytes: 32,
  ivBytes: 12,
  tagBytes: 16,
};

// HKDF domain-separation info prefixes
const INFO_ENTRY = 'pyxpass-entry:';
const INFO_ENC = 'pyxpass-enc:';

/** Generate a fresh 16-byte master-key salt. */
export function generateSalt() {
  return randomBytes(16);
}

/** Generate a fresh 12-byte GCM IV. */
export function newIv() {
  return randomBytes(AES_GCM.ivBytes);
}

/**
 * masterKey = Argon2id(masterPassword, salt)
 * Returns the raw 32-byte key. `@node-rs/argon2` returns the PHC-encoded
 * string, so the base64 hash segment is decoded to recover the raw bytes.
 */
export async function deriveMasterKey(password, salt) {
  const enc = await hash(Buffer.from(String(password), 'utf8'), {
    algorithm: Algorithm.Argon2id,
    memoryCost: ARGON2.memoryCost,
    timeCost: ARGON2.timeCost,
    parallelism: ARGON2.parallelism,
    outputLen: ARGON2.outputLen,
    salt: Buffer.from(salt),
  });
  // PHC format: $argon2id$v=19$m=..,t=..,p=..$<saltB64>$<hashB64>
  return Buffer.from(enc.split('$').pop(), 'base64');
}

/**
 * entryKey = HKDF-SHA256(masterKey, info="pyxpass-entry:<entryId>")
 * Per-entry key, domain-separated by entryId.
 */
export function deriveEntryKey(masterKey, entryId) {
  return hkdfSync('sha256', masterKey, Buffer.alloc(0), `${INFO_ENTRY}${entryId}`, AES_GCM.keyBytes);
}

/**
 * encKey = HKDF-SHA256(entryKey, info="pyxpass-enc:<rotation>:<entryId>")
 * Includes rotation so bumping the rotation counter changes every encKey.
 */
export function deriveEncKey(entryKey, rotation, entryId) {
  return hkdfSync(
    'sha256',
    entryKey,
    Buffer.alloc(0),
    `${INFO_ENC}${rotation}:${entryId}`,
    AES_GCM.keyBytes,
  );
}

/**
 * AES-256-GCM encrypt.
 * @param {Buffer|Uint8Array} plaintext
 * @param {Buffer} encKey 32-byte key
 * @returns {{ ciphertext: Buffer, iv: Buffer }} ciphertext includes the 16-byte GCM tag
 */
export function encrypt(plaintext, encKey) {
  const iv = newIv();
  const cipher = createCipheriv('aes-256-gcm', encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: Buffer.concat([ciphertext, tag]), iv };
}

/**
 * AES-256-GCM decrypt. Expects `payload` = ciphertext || 16-byte tag.
 * @param {Buffer} payload
 * @param {Buffer} iv
 * @param {Buffer} encKey
 * @returns {Buffer} plaintext
 * @throws on auth-tag mismatch (wrong key / tampered data)
 */
export function decrypt(payload, iv, encKey) {
  const payloadBuf = Buffer.from(payload);
  const tag = payloadBuf.subarray(payloadBuf.length - AES_GCM.tagBytes);
  const ciphertext = payloadBuf.subarray(0, payloadBuf.length - AES_GCM.tagBytes);
  const decipher = createDecipheriv('aes-256-gcm', encKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Full entry derivation: password -> masterKey -> entryKey -> encKey -> encrypt.
 * @returns {{ ciphertext: Buffer, iv: Buffer, version: number }}
 */
export async function encryptEntry(password, salt, entryId, rotation, plaintext) {
  const masterKey = await deriveMasterKey(password, salt);
  const entryKey = deriveEntryKey(masterKey, entryId);
  const encKey = deriveEncKey(entryKey, rotation, entryId);
  const { ciphertext, iv } = encrypt(plaintext, encKey);
  return { ciphertext, iv, version: CRYPTO_VERSION };
}

/**
 * Full entry decryption. Returns plaintext Buffer, or throws on wrong
 * password / rotation / tampered ciphertext.
 */
export async function decryptEntry(password, salt, entryId, rotation, payload, iv) {
  const masterKey = await deriveMasterKey(password, salt);
  const entryKey = deriveEntryKey(masterKey, entryId);
  const encKey = deriveEncKey(entryKey, rotation, entryId);
  return decrypt(payload, iv, encKey);
}

export default {
  CRYPTO_VERSION,
  ARGON2,
  AES_GCM,
  generateSalt,
  newIv,
  deriveMasterKey,
  deriveEntryKey,
  deriveEncKey,
  encrypt,
  decrypt,
  encryptEntry,
  decryptEntry,
};
