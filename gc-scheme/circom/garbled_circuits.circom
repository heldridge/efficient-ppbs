pragma circom 2.0.0;

include "./garbled_gates.circom";

template GarbledZCOBC() {
    signal input x[2][254];
    signal input y[2][254];
    signal input offset[254];
    signal input baseId;

    signal output out[2][254];
    signal output tG[254];
    signal output tE[254];
    signal output newId;

    component ng = GarbledNOT(253);
    component ag = GarbledAND();

    ng.in <== y;

    ag.a <== x;
    ag.b <== ng.out;
    ag.offset <== offset;

    // ZCOBC gets id
    // NOT gate gets id + 1
    // AND gate gets id + 2
    // So internal gates get +3 and +4
    ag.gGateId <== baseId + 3;
    ag.eGateId <== baseId + 4;
    // Next id is +5
    newId <== baseId + 5;

    out <== ag.out;
    tG <== ag.tG;
    tE <== ag.tE;
}

template GarbledOBC() {
    signal input x[2][254];
    signal input y[2][254];
    signal input c[2][254];
    signal input offset[254];
    signal input baseId;

    signal output out[2][254];
    signal output tG[254];
    signal output tE[254];
    signal output newId;

    component xXorC = GarbledXOR(253);
    component yXorC = GarbledXOR(253);
    component ng = GarbledNOT(253);
    component ag = GarbledAND();
    component finalXor = GarbledXOR(253);

    xXorC.a <== x[0];
    xXorC.b <== c[0];
    xXorC.offset <== offset;

    yXorC.a <== y[0];
    yXorC.b <== c[0];
    yXorC.offset <== offset;

    ng.in <== yXorC.out;

    ag.a <== xXorC.out;
    ag.b <== ng.out;
    ag.offset <== offset;
    ag.gGateId <== baseId + 5;
    ag.eGateId <== baseId + 6;

    finalXor.a <== c[0];
    finalXor.b <== ag.out[0];
    finalXor.offset <== offset;

    out <== finalXor.out;
    newId <== baseId + 8;
    tG <== ag.tG;
    tE <== ag.tE;


    // OBC gets id
    // xXorC gets id + 1
    // yXorC gets id + 2
    // ng gets id + 3
    // ag gets id + 4
    // internal ag gates get +5 and +6
    // finalXor gets +7
    // Next id is +8
}

template GarbledEBC(ell) {
    // Want at least the base comparator
    assert(ell > 0);

    signal input xInputs[ell][2][254];
    signal input yInputs[ell][2][254];
    signal input offset[254];

    signal output out[2][254];
    signal output tGs[ell][254];
    signal output tEs[ell][254];

    component zcobc = GarbledZCOBC();
    zcobc.x <== xInputs[0];
    zcobc.y <== yInputs[0];
    zcobc.offset <== offset;
    zcobc.baseId <== 2; // The EBC gets id 1

    tGs[0] <== zcobc.tG;
    tEs[0] <== zcobc.tE;

    component comparators[ell - 1];

    for(var i = 0; i < ell - 1; i++) {
        comparators[i] = GarbledOBC();
        comparators[i].x <== xInputs[i + 1];
        comparators[i].y <== yInputs[i + 1];
        comparators[i].offset <== offset;

        if (i == 0) {
            comparators[i].c <== zcobc.out;
            comparators[i].baseId <== zcobc.newId;
        } else {
            comparators[i].c <== comparators[i - 1].out;
            comparators[i].baseId <== comparators[i - 1].newId;
        }


        tGs[i + 1] <== comparators[i].tG;
        tEs[i + 1] <== comparators[i].tE;
    }

    if (ell == 1) {
        out <== zcobc.out;
    } else {
        out <== comparators[ell - 2].out;
    }
}
