pragma circom 2.0.0;

include "../../circomlib/circuits/bitify.circom";
include "./ot.circom";
include "./garbled_circuits.circom";
include "./utils.circom";

template MultiPairEncode(N) {
    signal input pairs[N][2];
    signal input rs[N][2][2];

    signal output encodings[N][2][3];

    component babyEncodes[N][2];

    for(var i = 0; i < N; i ++) {
        for (var j = 0; j < 2; j++) {
            babyEncodes[i][j] = BabyEncode();
            babyEncodes[i][j].m <== pairs[i][j];
            babyEncodes[i][j].r <== rs[i][j];

            encodings[i][j][0] <== babyEncodes[i][j].jubPoint[0];
            encodings[i][j][1] <== babyEncodes[i][j].jubPoint[1];
            encodings[i][j][2] <== babyEncodes[i][j].xIncrement;
        }
    }
}

template OptionsSelector(N) {
    signal input options[N][2];
    signal input selections[N];

    signal output out[N];

    for(var i = 0; i < N; i ++) {
        out[i] <== ((options[i][1] - options[i][0]) * selections[i]) + options[i][0];
        // out[i] <== options[i][1];
    }
}

template EncodeAndSend(ell) {
    signal input receiverWireLabels[ell][2];
    signal input receiverMessages[ell][2][2];
    signal input rEncodes[ell][2][2];
    signal input rEncrypt;
    signal input g[2];

    signal output responses[ell][2][5];

    component multiPairEncode = MultiPairEncode(ell);
    multiPairEncode.pairs <== receiverWireLabels;
    multiPairEncode.rs <== rEncodes;

    component multiSenderMessage = MultiSenderMessage(ell);
    multiSenderMessage.r <== rEncrypt;
    multiSenderMessage.g <== g;
    multiSenderMessage.encodings <== multiPairEncode.encodings;
    multiSenderMessage.receiverMessages <== receiverMessages;

    responses <== multiSenderMessage.responses;
}

template Pipeline(ell) {
    // Input
    //// Prover labels & choices
    signal input proverLabels[ell][2];    
    signal input proverSelectors[ell][2];
    signal input proverInput[ell];
    //// Validator labels & OT constants
    signal input receiverLabels[ell][2];
    signal input receiverSelectors[ell][2];
    signal input receiverMessages[ell][2][2];
    signal input rEncodes[ell][2][2];
    signal input rEncrypt;
    signal input g[2];

    //// GC Offset
    signal input offset[254];
    
    // Output
    //// Prover choices
    signal output proverLabelsOut[ell];
    signal output proverSelectorsOut[ell];
    //// Encrypted receiver labels
    signal output senderMessages[ell][2][5];
    //// GC Outputs
    signal output gcOut[2][254];
    signal output gcTGs[ell][254];
    signal output gcTEs[ell][254];

    // Send all prover wirelabel information
    //// Send labels
    component labelSel = OptionsSelector(ell);
    labelSel.options <== proverLabels;
    labelSel.selections <== proverInput;
    proverLabelsOut <== labelSel.out;
    //// Send Selectors
    component selectorSel = OptionsSelector(ell);
    selectorSel.options <== proverSelectors;
    selectorSel.selections <== proverInput;
    proverSelectorsOut <== selectorSel.out;
    
    // Encode and send receiver labels
    component eas = EncodeAndSend(ell);
    eas.receiverWireLabels <== receiverLabels;
    eas.receiverMessages <== receiverMessages;
    eas.rEncodes <== rEncodes;
    eas.rEncrypt <== rEncrypt;
    eas.g <== g;
    senderMessages <== eas.responses;
    
    // Create garbled circuit
    component gc = GarbledEBC(ell);
    gc.offset <== offset;

    // Reconstruct WireValues
    component pRecon = MultiPairNASTW(ell);
    pRecon.numPairs <== proverLabels;
    pRecon.selPairs <== proverSelectors;
    
    component rRecon = MultiPairNASTW(ell);
    rRecon.numPairs <== receiverLabels;
    rRecon.selPairs <== receiverSelectors; 
    
    gc.xInputs <== rRecon.out;
    gc.yInputs <== pRecon.out;
    gcOut <== gc.out;
    gcTGs <== gc.tGs;
    gcTEs <== gc.tEs;
}
