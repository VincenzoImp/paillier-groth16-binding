pragma circom 2.1.6;

include "../../circuits/node_modules/circomlib/circuits/poseidon.circom";
include "../../circuits/node_modules/circomlib/circuits/mux1.circom";

template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

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

template EligibilityOnly(levels) {
    signal input secret;
    signal input address;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal input root;
    signal input nullifier;
    signal input nullifierDomain;
    signal input voteHash;

    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== address;
    leafHasher.inputs[1] <== secret;

    component tree = MerkleTreeChecker(levels);
    tree.leaf <== leafHasher.out;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    root === tree.root;

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== nullifierDomain;
    nullifier === nullifierHasher.out;

    voteHash === voteHash;
}

component main {public [root, nullifier, nullifierDomain, voteHash]} = EligibilityOnly(10);
