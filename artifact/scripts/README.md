# Scripts

**These scripts are illustrative convenience tools, not the main source of
evidence.** The main reproducible evidence comes from the contract test suites
(37 tests including real Groth16 proofs, attack reproduction, aggregate
consistency, and ablation) and the crypto test suite (94 tests).

The scripts below demonstrate the same logic in a standalone format suitable
for quick inspection, but they operate on synthetic data rather than on-chain
traces.

## Scripts

- `attack-replay.ts` / `attack-replay.mjs`
  Reconstructs the naive-composition attack logic and shows why the bound
  statement diverges for substituted ciphertexts. Uses synthetic ciphertext
  pairs, not an on-chain replay.
- `transcript-reconstruction.ts` / `transcript-reconstruction.mjs`
  Builds a canonical transcript object from synthetic data, normalizes it,
  and emits a digest. For on-chain transcript reconstruction, see
  `AggregateConsistency.test.ts` which reads ballot records from the contract.

## Commands

```bash
yarn quick:attack
yarn attack:demo
yarn transcript:demo
```
