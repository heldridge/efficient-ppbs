pragma circom 2.0.0;

include "pipeline.circom";

component main {public [g, receiverMessages, rEncodes]} = Pipeline(32);
