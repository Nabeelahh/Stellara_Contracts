// Simple illustrative circuit: prove age >= 18 without revealing exact age
pragma circom 2.0.0;

template IsAdult() {
    signal input age; // private input
    signal output out;
    // checks: age - 18 >= 0
    out <== age >= 18;
}

component main = IsAdult();
