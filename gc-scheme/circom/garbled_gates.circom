pragma circom 2.0.0;

include "../../circomlib/circuits/bitify.circom";
include "../../circomlib/circuits/gates.circom";
include "../../circomlib/circuits/poseidon.circom";

template GarbledNOT(N) {
    // Two labels go in
    // Each is N bits + 1 selector bit
    signal input in[2][N + 1];

    // Two labels go out;
    signal output out[2][N + 1];

    // Swap the labels
    in[0] ==> out[1];
    in[1] ==> out[0];
}

template NBitXOR(N) {
    signal input a[N];
    signal input b[N];
    signal output out[N];

    component xors[N];

    for (var i = 0; i < N; i ++) {
        xors[i] = XOR();
        a[i] ==> xors[i].a;
        b[i] ==> xors[i].b;
        xors[i].out ==> out[i];
    }
}

template GarbledXOR(N) {
    // Only need the zero labels
    // Mostly keep labels as bit arrays, as XORs are the bulk of our operations.
    signal input a[N + 1];
    signal input b[N + 1];
    // Free-xor offset
    signal input offset[N + 1];

    // Two labels go out
    signal output out[2][N + 1];

    component nbx0 = NBitXOR(N + 1);
    component nbx1 = NBitXOR(N + 1);

    // XOR the zero values
    a ==> nbx0.a;
    b ==> nbx0.b;
    nbx0.out ==> out[0];

    // XOR the resulting value with the offset
    out[0] ==> nbx1.a;
    offset ==> nbx1.b;
    nbx1.out ==> out[1];
}

template LabelToNumber() {
    signal input label[253];
    signal output out;

    component b2n = Bits2Num(253);
    b2n.in <== label;
    out <== b2n.out;
}

template HashLabel() {
    signal input label[253];
    signal input gateID;

    signal output out[254];

    component l2n = LabelToNumber();
    component poseidon = Poseidon(2);
    component n2b = Num2Bits_strict();

    l2n.label <== label;
    poseidon.inputs[0] <== l2n.out;
    poseidon.inputs[1] <== gateID;

    n2b.in <== poseidon.out;

    out <== n2b.out;
}

template MultiMult(N) {
    signal input arr[N];
    signal input m;

    signal output out[N];

    for (var i = 0; i < N; i ++) {
        out[i] <== arr[i] * m;
    }
}

template GeneratorHalfGate(N) {
    signal input hashA0[N + 1];
    signal input hashA1[N + 1];
    signal input pB;
    signal input offset[N + 1];

    signal output out[N + 1];

    component hashXOR = NBitXOR(N + 1);
    hashA0 ==> hashXOR.a;
    hashA1 ==> hashXOR.b;

    component mm = MultiMult(N + 1);
    offset ==> mm.arr;
    pB ==> mm.m;

    component finalXOR = NBitXOR(N + 1);
    hashXOR.out ==> finalXOR.a;
    mm.out ==> finalXOR.b;
    finalXOR.out ==> out;
}

template EvaluatorHalfGate(N) {
    signal input hashB0[N + 1];
    signal input hashB1[N + 1];
    signal input a0[N + 1];

    signal output out[N + 1];

    component xor1 = NBitXOR(N + 1);
    component xor2 = NBitXOR(N + 1);

    hashB0 ==> xor1.a;
    hashB1 ==> xor1.b;
    xor1.out ==> xor2.a;
    a0 ==> xor2.b;

    xor2.out ==> out;
}

template HalfGateWG0(N) {
    signal input hashA0[N + 1];
    signal input pA;
    signal input genGate[N + 1];
    signal output out[N + 1];

    component mm = MultiMult(N + 1);
    genGate ==> mm.arr;
    pA ==> mm.m;

    component xor = NBitXOR(N + 1);
    hashA0 ==> xor.a;
    mm.out ==> xor.b;

    xor.out ==> out;
}

template HalfGateWE0(N) {
    signal input hashB0[N + 1];
    signal input pB;
    signal input evalGate[N + 1];
    signal input a0[N + 1];

    signal output out[N + 1];

    component xor1 = NBitXOR(N + 1);
    xor1.a <== evalGate;
    xor1.b <== a0;

    component mm = MultiMult(N + 1);
    mm.arr <== xor1.out;
    mm.m <== pB;

    component xor2 = NBitXOR(N + 1);
    xor2.a <== hashB0;
    xor2.b <== mm.out;

    out <== xor2.out;
}

template Selector() {
    signal input wireValue[254];
    signal output out;

    out <== wireValue[0];
}

template GarbledAND() {
    // zero and one labels for input wires
    signal input a[2][254];
    signal input b[2][254];
    // Free-xor offset
    signal input offset[254];
    // Unique IDs for the gate
    signal input gGateId;
    signal input eGateId;

    // Output wire labels
    signal output out[2][254];

    // Garbled half gates
    signal output tG[254];
    signal output tE[254];

    // Selector bits
    signal pA;
    signal pB;
    component selA = Selector();
    component selB = Selector();
    selA.wireValue <== a[0];
    selB.wireValue <== b[0];
    selA.out ==> pA;
    selB.out ==> pB;

    // INPUT PROCESSING
    // Here we convert each input to a number, hash it, then convert it back into bits
    var inputVals[4][254] = [a[0], a[1], b[0], b[1]];
    component labelHashes[4];

    for(var i = 0; i < 4; i ++) {
        labelHashes[i] = HashLabel();
        if ( i < 2 ) {
            gGateId ==> labelHashes[i].gateID;
        } else {
            eGateId ==> labelHashes[i].gateID;
        }

        for(var j = 0; j < 253; j++) {
            inputVals[i][j+1] ==> labelHashes[i].label[j];
        }
    }

    component genGate = GeneratorHalfGate(253);
    genGate.hashA0 <== labelHashes[0].out;
    genGate.hashA1 <== labelHashes[1].out;
    genGate.pB <== pB;
    genGate.offset <== offset;

    component wG0 = HalfGateWG0(253);
    wG0.hashA0 <== labelHashes[0].out;
    wG0.pA <== pA;
    wG0.genGate <== genGate.out;

    component evalGate = EvaluatorHalfGate(253);
    evalGate.hashB0 <== labelHashes[2].out;
    evalGate.hashB1 <== labelHashes[3].out;
    evalGate.a0 <== a[0];

    component wE0 = HalfGateWE0(253);
    wE0.hashB0 <== labelHashes[2].out;
    wE0.pB <== pB;
    wE0.evalGate <== evalGate.out;
    wE0.a0 <== a[0];

    tG <== genGate.out;
    tE <== evalGate.out;

    component xor = NBitXOR(254);
    xor.a <== wG0.out;
    xor.b <== wE0.out;
    out[0] <== xor.out;

    component offsetXor = NBitXOR(254);
    offsetXor.a <== out[0];
    offsetXor.b <== offset;
    out[1] <== offsetXor.out;
}
