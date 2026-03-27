Identity & SBT feature

This module implements Verifiable Credential issuance and optional on-chain Soulbound Token (SBT) minting.

Quick start

- Set environment variables in `Backend/.env` or environment:
  - `ETH_RPC_URL` - Ethereum RPC endpoint
  - `SBT_ISSUER_PRIVATE_KEY` - issuer private key for signing and on-chain txs
  - `SBT_CONTRACT_ADDRESS` - deployed SBT contract address (optional)
  - `RELAYER_PRIVATE_KEY` - relayer key for gasless meta-tx (optional)

- Endpoints:
  - `POST /identity/issue` - issue VC and optionally mint SBT
  - `POST /identity/revoke` - revoke on-chain token
  - `POST /identity/renew` - renew token expiration

Notes

- The module provides skeleton adapters for EBSI, uPort, and Civic integrations and a simple meta-relayer.
- Zero-knowledge circuits are included under `Contracts/circuits` as examples; run standard Circom/snarkjs flows to produce artifacts.
