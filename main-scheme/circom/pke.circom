pragma circom 2.0.0;

include "../../circuits/encrypt.circom";
include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/babyjub.circom";


template RREncRevealDet() {
    // params
    signal input q;
    signal input g[2];
    signal input h[2];

    signal input pk[2][2];
    signal input msg[2];
    signal input r;

    signal output out[2][2];

    component ege = ElGamalEncrypt();
    ege.m <== msg;
    ege.g <== g;
    ege.h <== pk[0];
    ege.y <== r;

    component rBits = Num2Bits(254);
    rBits.in <== r;
    component ema = EscalarMulAny(254);
    ema.e <== rBits.out;
    ema.p <== pk[1];

    out[0] <== ema.out; // CBar
    out[1] <== ege.c2; // C
}

template RREncMatchDet() {
    // params
    signal input q;
    signal input g[2];
    signal input h[2];

    signal input pk[2][2];
    signal input mask[2][2];
    signal input r;

    signal output out[2][2];

    component ege0 = ElGamalEncrypt();
    ege0.m <== mask[0];
    ege0.g <== g;
    ege0.h <== pk[1];
    ege0.y <== r;

    component ege1 = ElGamalEncrypt();
    ege1.m <== mask[1];
    ege1.g <== g;
    ege1.h <== pk[0];
    ege1.y <== r;

    out[0] <== ege0.c2;
    out[1] <== ege1.c2;
}

template RROTPEncCiphertext() {
    signal input mask[2][2];
    signal input ct[2][2];

    signal output out[2][2];

    signal CBar[2] <== ct[0];
    signal C[2] <== ct[1];

    component addBar = BabyAdd();
    addBar.x1 <== mask[0][0];
    addBar.y1 <== mask[0][1];
    addBar.x2 <== CBar[0];
    addBar.y2 <== CBar[1];

    component addReg = BabyAdd();
    addReg.x1 <== mask[1][0];
    addReg.y1 <== mask[1][1];
    addReg.x2 <== C[0];
    addReg.y2 <== C[1];

    out[0][0] <== addBar.xout;
    out[0][1] <== addBar.yout;
    out[1][0] <== addReg.xout;
    out[1][1] <== addReg.yout;
}

template RROTPEncMask() {
    signal input maskA[2][2];
    signal input maskB[2][2];

    signal output out[2][2];

    component add0 = BabyAdd();
    add0.x1 <== maskA[0][0];
    add0.y1 <== maskA[0][1];
    add0.x2 <== maskB[0][0];
    add0.y2 <== maskB[0][1];

    component add1 = BabyAdd();
    add1.x1 <== maskA[1][0];
    add1.y1 <== maskA[1][1];
    add1.x2 <== maskB[1][0];
    add1.y2 <== maskB[1][1];

    out[0][0] <== add0.xout;
    out[0][1] <== add0.yout;
    out[1][0] <== add1.xout;
    out[1][1] <== add1.yout;
}

template RROTPSingle() {
    signal input mask[2];
    signal input msg[2];

    signal output out[2];

    component add = BabyAdd();
    add.x1 <== mask[0];
    add.y1 <== mask[1];
    add.x2 <== msg[0];
    add.y2 <== msg[1];
    
    out[0] <== add.xout;
    out[1] <== add.yout;
}
