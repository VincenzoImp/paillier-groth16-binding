pragma circom 2.1.6;

include "../../circuits/node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../circuits/node_modules/circomlib/circuits/bitify.circom";

template Sha256Bridge6144() {
    signal input in[6144];
    signal output digestLo;
    signal output digestHi;

    component sha = Sha256(6144);
    for (var i = 0; i < 6144; i++) {
        sha.in[i] <== in[i];
    }

    component lo = Bits2Num(128);
    component hi = Bits2Num(128);

    for (var j = 0; j < 128; j++) {
        lo.in[j] <== sha.out[j];
        hi.in[j] <== sha.out[128 + j];
    }

    digestLo <== lo.out;
    digestHi <== hi.out;
}

component main = Sha256Bridge6144();
