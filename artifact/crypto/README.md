# Crypto Workspace

This package contains the research artifact's off-chain primitives:

- threshold Paillier helpers
- ballot validity proofs
- Merkle utilities
- proof generation for the cross-group binding circuit

The most important design choice in this lab version is that the ciphertext
limbs are part of the public signal vector. This lets the contract check that
the ciphertext bytes posted on-chain match the exact limbs committed by the
proof statement, avoiding the silent mismatch problem that appears when only a
digest is public but the contract never recomputes it.

## Modules

- `paillier/`
  Threshold Paillier key generation, encryption, aggregation, serialization,
  and decryption-share tooling.
- `zkp/`
  Poseidon Merkle utilities, nullifiers, proof generation helpers, and bound
  ballot packaging.

## Current scope

The crypto workspace already supports:

- full-limb ciphertext decomposition
- vote-hash computation
- bound ballot package construction
- threshold Paillier helpers

The crypto workspace does not yet ship:

- generated circuit artifacts in-repo
- a production ballot-validity proof system
- a proof-carrying aggregate correctness layer
