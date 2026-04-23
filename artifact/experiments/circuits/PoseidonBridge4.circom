pragma circom 2.1.6;

include "../../circuits/node_modules/circomlib/circuits/poseidon.circom";
include "../../circuits/node_modules/circomlib/circuits/bitify.circom";

template PoseidonBridge4() {
    signal input ctLimbs[4];
    signal output voteHash;

    component ctRangeCheck[4];
    for (var i = 0; i < 4; i++) {
        ctRangeCheck[i] = Num2Bits(192);
        ctRangeCheck[i].in <== ctLimbs[i];
    }

    component leftHash = Poseidon(2);
    leftHash.inputs[0] <== ctLimbs[0];
    leftHash.inputs[1] <== ctLimbs[1];

    component rightHash = Poseidon(2);
    rightHash.inputs[0] <== ctLimbs[2];
    rightHash.inputs[1] <== ctLimbs[3];

    component rootHash = Poseidon(2);
    rootHash.inputs[0] <== leftHash.out;
    rootHash.inputs[1] <== rightHash.out;

    voteHash <== rootHash.out;
}

component main = PoseidonBridge4();
