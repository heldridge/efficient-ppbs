pragma circom 2.0.0;

include "./vecd.circom";

component main {public [q, g, h, pk]} = RRVECDEncryptDet(11, 41);
