pragma circom 2.0.0;

include "../../circomlib/circuits/bitify.circom";

template NumAndSelToWirevalue() {
    signal input num;
    signal input sel;
    signal output out[254];

    component n2b = Num2Bits(253);
    n2b.in <== num;

    out[0] <== sel;
    for(var i = 0; i < 253; i ++) {
        out[i+1] <== n2b.out[i];
    }
}

template PairNumAndSelToWirevalue() {
    signal input nums[2];
    signal input sels[2];
    signal output out[2][254];

    component NASTWs[2];

    for(var j = 0; j < 2; j++) {
        NASTWs[j] = NumAndSelToWirevalue();
        NASTWs[j].num <== nums[j];
        NASTWs[j].sel <== sels[j];
        out[j] <== NASTWs[j].out;
    }
}

template MultiPairNASTW(ell) {
    signal input numPairs[ell][2];
    signal input selPairs[ell][2];
    signal output out[ell][2][254];

    component PNASTWs[ell];

    for(var i = 0; i < ell; i++)  {
        PNASTWs[i] = PairNumAndSelToWirevalue();
        PNASTWs[i].nums <== numPairs[i];
        PNASTWs[i].sels <== selPairs[i];
        out[i] <== PNASTWs[i].out;
    }
}