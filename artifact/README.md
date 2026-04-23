# Artifact

This artifact is deliberately narrower than the broader research workflow that
produced it.

It exists to support one research question:

- naive composition of threshold Paillier ciphertexts and SNARK-based
  eligibility proofs is insecure across incompatible algebraic groups
- cross-group binding closes that gap
- voting is the flagship case study, not the only possible application

## Subdirectories

- `contracts/`
  Bulletin-board contract and contract tests.
- `circuits/`
  Circom circuit for eligibility plus ciphertext-limb binding.
- `crypto/`
  Off-chain Paillier and proof-side helpers.
- `scripts/`
  Scripted attack/defense and transcript reconstruction.
- `experiments/`
  Overhead and benchmarking utilities.
- `demo/`
  Thin demo guidance. The repository is intentionally not UI-first.

## Artifact Boundaries

The current artifact explicitly demonstrates:

- bound ballot formation
- on-chain limb consistency checks
- nullifier uniqueness
- transcript generation
- aggregate publication
- share publication
- finalization gating

The current artifact intentionally does not claim:

- full on-chain tally correctness
- on-chain DLEQ verification
- coercion resistance
- receipt-freeness
- production committee management

## Quick Demo Path

The shortest executable path is:

```bash
yarn quick:attack
```

This runs the real-verifier `AttackDemo` tests and is the shortest executable
route to the artifact's core claim. The script-level companion is:

```bash
yarn attack:demo
```
