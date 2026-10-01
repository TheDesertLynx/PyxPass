#!/usr/bin/env node
//
// Top up the PyxPass identity's credit balance from the platform address.
//
// Usage: node topup-identity.mjs [amountCredits]
//   amountCredits defaults to 30,000,000,000 (30B) — enough for contract
//   registration + document ops with buffer.
//
import { setupDashClient } from './setupDashClient.mjs';

const { sdk, keyManager, addressKeyManager } = await setupDashClient({
  requireIdentity: true,
});
const signer = addressKeyManager.getSigner();
const amount = BigInt(process.argv[2] || 30_000_000_000n);

try {
  const identity = await sdk.identities.fetch(keyManager.identityId);
  const result = await sdk.addresses.topUpIdentity({
    identity,
    inputs: [
      {
        address: addressKeyManager.primaryAddress.bech32m,
        amount,
      },
    ],
    signer,
  });
  console.log(`Top-up result:
  Identity: ${keyManager.identityId}
  Amount:   ${amount} credits
  Start:    ${identity.toJSON().balance}
  Final:    ${result.newBalance}`);
} catch (e) {
  console.error('Something went wrong:\n', e.message);
} finally {
  await sdk.disconnect?.().catch(() => {});
}
