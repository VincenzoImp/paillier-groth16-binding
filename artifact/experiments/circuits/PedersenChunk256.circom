pragma circom 2.1.6;

include "../../circuits/node_modules/circomlib/circuits/pedersen.circom";

template PedersenChunk256() {
    signal input in[256];
    signal output out[2];

    component pedersen = Pedersen(256);
    for (var i = 0; i < 256; i++) {
        pedersen.in[i] <== in[i];
    }

    out[0] <== pedersen.out[0];
    out[1] <== pedersen.out[1];
}

component main = PedersenChunk256();
