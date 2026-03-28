# ZK Circuit Artifacts

This directory holds compiled Circom artifacts for zero-knowledge proofs.

Expected file layout:

- `solvency/solvency.wasm`
- `solvency/solvency.zkey`
- `solvency/solvency_verification_key.json`

## Generating circuits

1. Write a Circom circuit in `circuits/solvency.circom`.
2. Compile it using `circom`.
3. Run the trusted setup to generate `.zkey` and verification key.
4. Place the compiled artifacts under `Backend/src/zk/circuits/solvency/`.

The `ZkService` implementation expects these artifacts to exist before proof generation and verification.
