//
// crypto.mjs — wallet-side DashConnect key-exchange crypto.
//
// Implementations are verified byte-for-byte against the dash wallet's
// KeyExchangeCryptoTests.swift vectors and the platform-auth kotlin fixtures:
//   - deriveAesKey(sharedX)          -> "0d14bc5a..."   (HKDF-SHA256, salt "dash:key-exchange:v1", info "")
//   - encryptLoginKey(...) payload   -> "10111213141516..." (nonce || ciphertext || tag, 60 bytes)
//   - deriveAuthKeyFromLogin(...)    -> "e06ee7ae..."   (info "auth")
//   - deriveEncryptionKeyFromLogin() -> "6879c118..."   (info "encryption")
//   - hash160                        -> ripemd160(sha256(x))
//   - login-key derivation           -> HKDF(chainKey, salt=identityId, info="dash:login-key:v1"||contractId)
//
// Uses only node:crypto. Zero external dependencies.
//

import crypto from 'node:crypto';

/** 32-byte HKDF-SHA256. */
function hkdfSha256(ikm, salt, info, length = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, length));
}

/** RIPEMD160(SHA256(data)) — the Platform identity/key hash. */
export function hash160(data) {
  const sha = crypto.createHash('sha256').update(data).digest();
  return crypto.createHash('ripemd160').update(sha).digest();
}

/** secp256k1 compressed public key (33 bytes) from a 32-byte private key. */
export function compressedPublicKey(privateKey) {
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKey);
  const uncompressed = ecdh.getPublicKey(); // 65 bytes: 0x04 || x || y
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);
  const prefix = y[31] & 1 ? 0x03 : 0x02;
  return Buffer.concat([Buffer.from([prefix]), x]);
}

/** secp256k1 ECDH: shared X coordinate (32 bytes) between priv and compressed pub. */
export function ecdhSharedX(privateKey, compressedPublicKey) {
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKey);
  return ecdh.computeSecret(compressedPublicKey);
}

/** Generate a fresh ephemeral keypair (wallet side of the exchange). */
export function generateEphemeralKeypair() {
  const privateKey = crypto.randomBytes(32);
  return { privateKey, publicKey: compressedPublicKey(privateKey) };
}

/**
 * Derive the AES key from the ECDH shared X coordinate.
 * HKDF-SHA256(ikm=sharedX, salt="dash:key-exchange:v1", info="", len=32).
 */
export function deriveAesKey(sharedX) {
  if (sharedX.length !== 32) throw new Error('Shared X coordinate must be exactly 32 bytes');
  return hkdfSha256(sharedX, Buffer.from('dash:key-exchange:v1'), Buffer.alloc(0), 32);
}

/**
 * Encrypt a login key into the 60-byte exchange envelope:
 *   payload = nonce(12) || AES-256-GCM-ciphertext || authTag
 * where AES key = deriveAesKey(ecdhSharedX(walletEphemeralPriv, appEphemeralPub)).
 */
export function encryptLoginKey(loginKey, walletEphemeralPriv, appEphemeralPub, nonce) {
  if (loginKey.length !== 32) throw new Error('Login key must be exactly 32 bytes');
  if (nonce.length !== 12) throw new Error('Nonce must be exactly 12 bytes');
  const sharedX = ecdhSharedX(walletEphemeralPriv, appEphemeralPub);
  const aesKey = deriveAesKey(sharedX);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(loginKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = Buffer.concat([nonce, ciphertext, tag]);
  if (payload.length !== 60) throw new Error('Encrypted payload must be exactly 60 bytes');
  // zero the ephemeral aes key + shared secret
  aesKey.fill(0);
  sharedX.fill(0);
  return payload;
}

/**
 * Decrypt a login-key envelope (tests / verification only).
 * payload = nonce(12) || ciphertext || tag.
 */
export function decryptLoginKey(payload, walletEphemeralPriv, appEphemeralPub) {
  if (payload.length !== 60) throw new Error('Encrypted payload must be exactly 60 bytes');
  const nonce = payload.subarray(0, 12);
  const ciphertextWithTag = payload.subarray(12);
  const sharedX = ecdhSharedX(walletEphemeralPriv, appEphemeralPub);
  const aesKey = deriveAesKey(sharedX);
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(ciphertextWithTag.subarray(-16));
  const loginKey = Buffer.concat([
    decipher.update(ciphertextWithTag.subarray(0, -16)),
    decipher.final(),
  ]);
  aesKey.fill(0);
  sharedX.fill(0);
  if (loginKey.length !== 32) throw new Error(`Invalid decrypted login key length: ${loginKey.length}`);
  return loginKey;
}

/**
 * Login-key derivation (wallet side, from the identity auth-chain key):
 *   loginKey = HKDF-SHA256(ikm=chainKey, salt=identityId, info="dash:login-key:v1" || contractId, len=32)
 * Matches LoginKeyDerivation.swift. The chain key is the identity's auth-chain
 * private key at key index 0 (LoginKeyDerivation.defaultKeyIndex).
 */
export function deriveLoginKey(chainKeyPrivateBytes, identityId, appContractId) {
  if (chainKeyPrivateBytes.length !== 32) throw new Error('Chain key must be exactly 32 bytes');
  if (identityId.length !== 32) throw new Error('Identity ID must be exactly 32 bytes');
  if (appContractId.length !== 32) throw new Error('App contract ID must be exactly 32 bytes');
  const info = Buffer.concat([Buffer.from('dash:login-key:v1'), appContractId]);
  return hkdfSha256(chainKeyPrivateBytes, identityId, info, 32);
}

/** App-side auth key from the recovered login key: HKDF(info="auth"). */
export function deriveAuthKeyFromLogin(loginKey, identityId) {
  if (loginKey.length !== 32) throw new Error('Login key must be exactly 32 bytes');
  if (identityId.length !== 32) throw new Error('Identity ID must be exactly 32 bytes');
  return hkdfSha256(loginKey, identityId, Buffer.from('auth'), 32);
}

/** App-side encryption key from the recovered login key: HKDF(info="encryption"). */
export function deriveEncryptionKeyFromLogin(loginKey, identityId) {
  if (loginKey.length !== 32) throw new Error('Login key must be exactly 32 bytes');
  if (identityId.length !== 32) throw new Error('Identity ID must be exactly 32 bytes');
  return hkdfSha256(loginKey, identityId, Buffer.from('encryption'), 32);
}

/** Zero a sensitive buffer in place (best-effort; JS buffers cannot be fully wiped). */
export function clearSensitiveBytes(bytes) {
  bytes.fill(0);
}

/** Hex helpers used by tests. */
export function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}
export function fromHex(hex) {
  return Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex');
}
