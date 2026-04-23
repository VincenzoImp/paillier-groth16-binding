pragma circom 2.1.6;

include "../../circuits/node_modules/circomlib/circuits/poseidon.circom";
include "../../circuits/node_modules/circomlib/circuits/bitify.circom";

template PoseidonBridge32() {
    signal input ctLimbs[32];
    signal output voteHash;

    component ctRangeCheck[32];
    for (var i = 0; i < 32; i++) {
        ctRangeCheck[i] = Num2Bits(192);
        ctRangeCheck[i].in <== ctLimbs[i];
    }

    component ctL0[16];
    for (var j = 0; j < 16; j++) {
        ctL0[j] = Poseidon(2);
        ctL0[j].inputs[0] <== ctLimbs[2 * j];
        ctL0[j].inputs[1] <== ctLimbs[2 * j + 1];
    }

    component ctL1[8];
    for (var k = 0; k < 8; k++) {
        ctL1[k] = Poseidon(2);
        ctL1[k].inputs[0] <== ctL0[2 * k].out;
        ctL1[k].inputs[1] <== ctL0[2 * k + 1].out;
    }

    component ctL2[4];
    for (var l = 0; l < 4; l++) {
        ctL2[l] = Poseidon(2);
        ctL2[l].inputs[0] <== ctL1[2 * l].out;
        ctL2[l].inputs[1] <== ctL1[2 * l + 1].out;
    }

    component ctL3[2];
    for (var m = 0; m < 2; m++) {
        ctL3[m] = Poseidon(2);
        ctL3[m].inputs[0] <== ctL2[2 * m].out;
        ctL3[m].inputs[1] <== ctL2[2 * m + 1].out;
    }

    component ctRoot = Poseidon(2);
    ctRoot.inputs[0] <== ctL3[0].out;
    ctRoot.inputs[1] <== ctL3[1].out;

    voteHash <== ctRoot.out;
}

component main = PoseidonBridge32();
