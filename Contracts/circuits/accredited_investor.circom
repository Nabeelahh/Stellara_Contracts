// Illustrative circuit for accredited investor boolean claim
pragma circom 2.0.0;

template Accredited() {
  signal input accredited; // 1 if accredited, 0 otherwise
  signal output out;
  out <== accredited == 1;
}

component main = Accredited();
