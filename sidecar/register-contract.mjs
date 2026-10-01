#!/usr/bin/env node
//
// Register the PyxPass data contract on testnet (Milestone 3).
//
// Prerequisites:
//   1. Identity registered (run register-identity.mjs) — set config/testnet.json identity.id
//   2. Identity has a credit balance
//
// Prints the Contract ID — copy it into config/testnet.json -> contract.id.
//
import { readFile } from 'node:fs/promises';
import { DataContract } from '@dashevo/evo-sdk';
import { setupDashClient } from './setupDashClient.mjs';
import { contractSchema } from './contract.schema.mjs';

const { sdk, keyManager } = await setupDashClient({ requireIdentity: true });
const { identity, identityKey, signer } = await keyManager.getAuth();

// Load config for identity id (validated against the resolved on-chain identity)
try {
  const cfg = JSON.parse(
    await readFile(new URL('../config/testnet.json', import.meta.url), 'utf8'),
  );
  const cfgId = cfg.identity?.id;
  if (cfgId && cfgId !== identity.id.toString()) {
    console.warn(
      `Warning: config identity.id (${cfgId}) differs from resolved identity (${identity.id}). Using resolved identity.`,
    );
  }
} catch {
  /* config absent — use resolved identity */
}

try {
  // Get the next identity nonce for contract creation
  const identityNonce = await sdk.identities.nonce(identity.id.toString());

  // Create the data contract (history disabled by default)
  const dataContract = new DataContract({
    ownerId: identity.id,
    identityNonce: (identityNonce || 0n) + 1n,
    schemas: contractSchema,
    fullValidation: true,
  });

  // Publish the contract to the platform
  const publishedContract = await sdk.contracts.publish({
    dataContract,
    identityKey,
    signer,
  });

  console.log('Contract registered:\n', publishedContract.toJSON());
  console.log('\nContract ID:', dataContract.id.toString());
} catch (e) {
  console.error('Something went wrong:\n', e.message);
} finally {
  await sdk.disconnect?.().catch(() => {});
}
