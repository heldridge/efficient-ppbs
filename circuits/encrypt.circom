pragma circom 2.0.0;

include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/bitify.circom";

template ElGamalEncrypt() {
    signal input m[2];  // Message point m on G
    signal input g[2];  // Base point of curve G
    signal input h[2];  // Public key point
    signal input y; // Random scalar y
    signal output c1[2]; // Output point c1
    signal output c2[2]; // Output point c2

    // Convert y to bits
    component yBits = Num2Bits(253);
    yBits.in <== y;

    // Compute shared secret s = h^y
    component sharedSecret = EscalarMulAny(253);

    for (var i = 0; i < 253; i ++) {
        sharedSecret.e[i] <== yBits.out[i];
    }
    sharedSecret.p[0] <== h[0];
    sharedSecret.p[1] <== h[1];

    // Compute c1 = g^y
    component c1Comp = EscalarMulAny(253);

    for (var i = 0; i < 253; i ++) {
        c1Comp.e[i] <== yBits.out[i];
    }
    c1Comp.p[0] <== g[0];
    c1Comp.p[1] <== g[1];
    c1[0] <== c1Comp.out[0];
    c1[1] <== c1Comp.out[1];

    // Compute c2 = m * s
    component c2Comp = BabyAdd();
    c2Comp.x1 <== m[0];
    c2Comp.y1 <== m[1];
    c2Comp.x2 <== sharedSecret.out[0];
    c2Comp.y2 <== sharedSecret.out[1];

    c2[0] <== c2Comp.xout;
    c2[1] <== c2Comp.yout;
}