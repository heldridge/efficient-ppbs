pragma circom 2.0.0;

include "../../circomlib/circuits/babyjub.circom";
include "../../circuits/encrypt.circom";

/*
Encodes a plaintext int to a BabyJub point
*
* m: The plaintext to encode. Element of Fp
* r: A random babyJub point
*
* xIncrement: The increment required to retrieve m from the BabyJub encoding
* jubPoint: The BabyJub encoding of m
*/
template BabyEncode() {
    signal input m;
    signal input r[2];
    signal output xIncrement;
    signal output jubPoint[2];


    r[0] - m ==> xIncrement;
    r ==> jubPoint;
}

/* Performs a single bit OT with BabyJub-ElGamal encryption
* r: The ElGamal mask. Element of Fp.
* g: The base-point of the BabyJub curve.
* encodings: The encodings of the messages to be sent by the sender
* msgZero: The value for zero sent by the OT receiver. BabyJub point.
* msgOne: The value for one sent by the OT reciever. BabyJub point.
*
* response: The message sent by the OT sender: (A pair of ELGamal ciphertexts + xIncrements)
*/
template SenderMessage() {
    signal input r;
    signal input g[2];

    // Have two different encodings, one for the zero and one for the one vals
    // Each encoding is thee values (point.x, point.y, xIncrement)
    signal input encodings[2][3];

    // Each receiver message (for 0 and 1) is two values (a public key)
    signal input receiverMessage[2][2];

    signal output response[2][5];

    component encZero = ElGamalEncrypt();
    component encOne = ElGamalEncrypt();

    encodings[0][0] ==> encZero.m[0];
    encodings[0][1] ==> encZero.m[1];
    g ==> encZero.g;
    receiverMessage[0] ==> encZero.h;
    r ==> encZero.y;


    encodings[1][0] ==> encOne.m[0];
    encodings[1][1] ==> encOne.m[1];
    g ==> encOne.g;
    receiverMessage[1] ==> encOne.h;
    r ==> encOne.y;

    encZero.c1[0] ==> response[0][0];
    encZero.c1[1] ==> response[0][1];
    encZero.c2[0] ==> response[0][2];
    encZero.c2[1] ==> response[0][3];
    encodings[0][2] ==> response[0][4];

    encOne.c1[0] ==> response[1][0];
    encOne.c1[1] ==> response[1][1];
    encOne.c2[0] ==> response[1][2];
    encOne.c2[1] ==> response[1][3];
    encodings[1][2] ==> response[1][4];
}

template MultiSenderMessage(N) {
    signal input r;
    signal input g[2];
    // We need to send N encodings
    signal input encodings[N][2][3];
    signal input receiverMessages[N][2][2];

    signal output responses[N][2][5];

    component senderMessages[N];

    for(var i = 0; i < N; i ++) {
        senderMessages[i] = SenderMessage();
        senderMessages[i].r <== r;
        senderMessages[i].g <== g;
        senderMessages[i].encodings <== encodings[i];
        senderMessages[i].receiverMessage <== receiverMessages[i];

        responses[i] <== senderMessages[i].response;
    }
}
