pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// Computes Poseidon hash of two inputs
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

// Verifies a Merkle proof path
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output root;

    component hashers[levels];
    component mux[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = HashLeftRight();
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i].left <== mux[i].out[0];
        hashers[i].right <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].hash;
    }

    root <== levelHashes[levels];
}

// Cross-group ballot circuit:
// - proves Merkle membership
// - derives the election-specific nullifier from a public nullifier domain
// - exposes the full 32-limb ciphertext decomposition as public input
// - constrains voteHash to be the Poseidon-Merkle root of those public limbs
template CrossGroupBallot(levels) {
    // Private inputs
    signal input secret;
    signal input address;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public inputs
    signal input root;
    signal input nullifier;
    signal input nullifierDomain;
    signal input voteHash;
    signal input ctLimbs[32];

    // Step 1: Compute leaf = Poseidon(address, secret)
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== address;
    leafHasher.inputs[1] <== secret;

    // Step 2: Verify Merkle path
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== leafHasher.out;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    // Step 3: Constrain computed root to match public root
    root === tree.root;

    // Step 4: Verify nullifier = Poseidon(secret, nullifierDomain)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== nullifierDomain;
    nullifier === nullifierHasher.out;

    // Step 5: Range-check each ctLimb to ensure it fits in 192 bits
    // (6144 total bits / 32 limbs = 192 bits per limb)
    // Without this, a malicious prover could supply limbs outside [0, 2^192),
    // breaking injectivity of the decomposition and thus binding security.
    component ctRangeCheck[32];
    for (var i = 0; i < 32; i++) {
        ctRangeCheck[i] = Num2Bits(192);
        ctRangeCheck[i].in <== ctLimbs[i];
    }

    // Step 6: Bind voteHash to ALL 6144 bits of the Paillier ciphertext
    // via a binary Poseidon Merkle tree over 32 limbs (depth 5).
    // This prevents the partial-binding attack where an adversary could
    // forge a different ciphertext sharing the same truncated prefix.

    // Level 0: 32 leaves -> 16 hashes
    component ctL0[16];
    for (var i = 0; i < 16; i++) {
        ctL0[i] = Poseidon(2);
        ctL0[i].inputs[0] <== ctLimbs[2*i];
        ctL0[i].inputs[1] <== ctLimbs[2*i + 1];
    }

    // Level 1: 16 -> 8
    component ctL1[8];
    for (var i = 0; i < 8; i++) {
        ctL1[i] = Poseidon(2);
        ctL1[i].inputs[0] <== ctL0[2*i].out;
        ctL1[i].inputs[1] <== ctL0[2*i + 1].out;
    }

    // Level 2: 8 -> 4
    component ctL2[4];
    for (var i = 0; i < 4; i++) {
        ctL2[i] = Poseidon(2);
        ctL2[i].inputs[0] <== ctL1[2*i].out;
        ctL2[i].inputs[1] <== ctL1[2*i + 1].out;
    }

    // Level 3: 4 -> 2
    component ctL3[2];
    for (var i = 0; i < 2; i++) {
        ctL3[i] = Poseidon(2);
        ctL3[i].inputs[0] <== ctL2[2*i].out;
        ctL3[i].inputs[1] <== ctL2[2*i + 1].out;
    }

    // Level 4: 2 -> 1 (root)
    component ctRoot = Poseidon(2);
    ctRoot.inputs[0] <== ctL3[0].out;
    ctRoot.inputs[1] <== ctL3[1].out;

    // Constrain voteHash to equal the Merkle root of all ciphertext limbs
    voteHash === ctRoot.out;
}

component main {public [root, nullifier, nullifierDomain, voteHash, ctLimbs]} = CrossGroupBallot(10);
