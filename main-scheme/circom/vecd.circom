pragma circom 2.0.0;

include "./pke.circom";
include "../../circuits/quin_selector.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/escalarmulany.circom";
include "../../circomlib/circuits/bitify.circom";

template ScalarToGroup() {
    signal input g[2];  // Base point of curve G
    signal input y; // scalar y  
    
    signal output out[2]; // g^y

    component yBits = Num2Bits(253);
    yBits.in <== y;

    component ema = EscalarMulAny(253);

    for (var i = 0; i < 253; i ++) {
        ema.e[i] <== yBits.out[i];
    }
    ema.p[0] <== g[0];
    ema.p[1] <== g[1];
    
    out <== ema.out;
}

template ConditionalEncryptReveal(n, b) {
    // PKE Params
    signal input q;
    signal input g[2];
    signal input h[2];

    signal input currentDigit;
    signal input r;
    signal input pkRow[b][2][2];
    signal input msg[2];

    signal output ct[2][2];

    component erdReal = RREncRevealDet();
    erdReal.q <== q;
    erdReal.g <== g;
    erdReal.h <== h;
    erdReal.r <== r;
    erdReal.msg <== msg;
    component QSD = QuinSelectorDouble(b);
    QSD.in <== pkRow;
    QSD.index <== currentDigit;
    erdReal.pk <== QSD.out;

    ct <== erdReal.out;
}

template RRVECDEncryptDet(n, b) {
    // PKE Params
    signal input q;
    signal input g[2];
    signal input h[2];

    // n rows, b columns, each with an X and XBar
    signal input pk[n][b][2][2];
    signal input baseArray[n];
    signal input m[2];
    // signal input alphas[n - 1][2][2];
    signal input otpStarRand;
    signal input otpRands[n - 1][2];
    signal input rReveal;
    signal input rMatch;

    signal output betaStar[2];
    signal output first[2][2][2];
    // n - 2 middle slots
    // Each has an OTPCT and an MCT component
    // Each of which is 2 BJPoints
    signal output middle[n - 2][2][2][2];
    signal output last[2][2];

    signal alphaStar[2];
    component stgStar = ScalarToGroup();
    stgStar.g <== g;
    stgStar.y <== otpStarRand;
    alphaStar <== stgStar.out;
    

    component starEnc = RROTPSingle();
    starEnc.mask <== alphaStar;
    starEnc.msg <== m;
    betaStar <== starEnc.out;
    


    signal alphas[n - 1][2][2];

    component stgs[n - 1][2];
    for (var i = 0; i < n - 1; i++) {
        for (var j = 0; j < 2; j++) {
            stgs[i][j] = ScalarToGroup();
            stgs[i][j].g <== g;
            stgs[i][j].y <== otpRands[i][j];
            alphas[i][j] <== stgs[i][j].out;
        }
    }


    component ctR0 = ConditionalEncryptReveal(n, b);
    ctR0.q <== q;
    ctR0.g <== g;
    ctR0.h <== h;
    ctR0.currentDigit <== baseArray[0];
    ctR0.r <== rReveal;
    ctR0.pkRow <== pk[0];
    ctR0.msg <== m;

    component ctM0 = RREncMatchDet();
    ctM0.q <== q;
    ctM0.g <== g;
    ctM0.h <== h;
    ctM0.mask <== alphas[0];
    ctM0.r <== rMatch;
    component QSD = QuinSelectorDouble(b);
    QSD.in <== pk[0];
    QSD.index <== baseArray[0] + 1;
    ctM0.pk <== QSD.out;

    
    component betaMis[n - 2];
    component ctRis[n - 2];
    component betaIs[n - 2];
    component ctMis[n - 2];
    component QSDs[n - 2];
    for (var i = 1; i < n - 1; i++) {
        betaMis[i - 1] = ConditionalEncryptReveal(n, b);
        betaMis[i - 1].q <== q;
        betaMis[i - 1].g <== g;
        betaMis[i - 1].h <== h;
        betaMis[i - 1].currentDigit <== baseArray[i];
        betaMis[i - 1].r <== rReveal;
        betaMis[i - 1].pkRow <== pk[i];
        betaMis[i - 1].msg <== alphaStar;

        ctRis[i - 1] = RROTPEncCiphertext();
        ctRis[i - 1].mask <== alphas[i - 1];
        ctRis[i - 1].ct <== betaMis[i-1].ct;

        betaIs[i - 1] = RROTPEncMask();
        betaIs[i - 1].maskA <== alphas[i - 1];
        betaIs[i - 1].maskB <== alphas[i];

        ctMis[i - 1] = RREncMatchDet();
        ctMis[i - 1].q <== q;
        ctMis[i - 1].g <== g;
        ctMis[i - 1].h <== h;
        ctMis[i - 1].mask <== betaIs[i - 1].out;
        ctMis[i - 1].r <== rMatch;
        QSDs[i - 1] = QuinSelectorDouble(b);
        QSDs[i - 1].in <== pk[i];
        QSDs[i - 1].index <== baseArray[i] + 1;
        ctMis[i - 1].pk <== QSDs[i-1].out;

        middle[i - 1][0] <== ctRis[i - 1].out;
        middle[i - 1][1] <== ctMis[i - 1].out;
    }

    component betaMFinal = ConditionalEncryptReveal(n, b);
    betaMFinal.q <== q;
    betaMFinal.g <== g;
    betaMFinal.h <== h;
    betaMFinal.currentDigit <== baseArray[n - 1];
    betaMFinal.r <== rReveal;
    betaMFinal.pkRow <== pk[n - 1];
    betaMFinal.msg <== alphaStar;

    component ctRFinal = RROTPEncCiphertext();
    ctRFinal.mask <== alphas[n - 2];
    ctRFinal.ct <== betaMFinal.ct;
    

    first[0] <== ctR0.ct;
    first[1] <== ctM0.out;
    last <== ctRFinal.out;
    //aux[0] <== rReveal;
    //aux[1] <== rMatch;
}
