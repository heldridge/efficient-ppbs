pragma circom 2.0.0;

include "../circomlib/circuits/comparators.circom";
// Source: https://github.com/darkforest-eth/circuits/blob/master/perlin/QuinSelector.circom

// Helper function to calculate the number of bits needed
function numBits(n) {
    var bits = 0;
    while (n > 0) {
        n = n >> 1;
        bits++;
    }
    return bits;
}

template CalculateTotal(n) {
    signal input in[n];
    signal output out;

    signal sums[n];

    sums[0] <== in[0];

    for (var i = 1; i < n; i++) {
        sums[i] <== sums[i-1] + in[i];
    }

    out <== sums[n-1];
}

template QuinSelector(choices) {
    signal input in[choices];
    signal input index;
    signal output out;
    
    // Calculate the number of bits needed to represent 'choices'
    var bitsNeeded = numBits(choices);

    // Ensure that index < choices
    component lessThan = LessThan(bitsNeeded);
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    lessThan.out === 1;

    component calcTotal = CalculateTotal(choices);
    component eqs[choices];

    // For each item, check whether its index equals the input index.
    for (var i = 0; i < choices; i ++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== index;

        // eqs[i].out is 1 if the index matches. As such, at most one input to
        // calcTotal is not 0.
        calcTotal.in[i] <== eqs[i].out * in[i];
    }

    // Returns 0 + 0 + 0 + item
    out <== calcTotal.out;
}

template QuinSelectorDouble(choices) {
    signal input in[choices][2][2];
    signal input index;
    signal output out[2][2];

    component QSs[2][2];
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 2; j++) {
            QSs[i][j] = QuinSelector(choices);
            QSs[i][j].index <== index;
            for (var k = 0; k < choices; k++) {
                QSs[i][j].in[k] <== in[k][i][j];
            }
            out[i][j] <== QSs[i][j].out;
        }
    }

}