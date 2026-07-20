# Integration Test Patterns

This guide documents the cross-contract testing patterns used in the Contracts workspace.

## Goals

- Validate end-to-end business flows that touch multiple contracts.
- Verify state transitions across contract boundaries in one scenario.
- Reuse shared governance expectations for upgradeable contracts.

## Core Patterns

### 1. Single Environment Orchestration

Run all contracts in one Soroban `Env` and register each contract in the same test.
This mirrors real deployments where contracts share a network state.

### 2. Scenario-Driven Assertions

Model realistic system flows instead of isolated method checks:

- Academy badge redemption followed by social reward crediting.
- Trading execution followed by fee transfer to recipient.
- External system flow followed by messaging notification delivery.

### 3. Shared Governance Validation

For all upgradeable contracts, assert the same governance lifecycle:

- `init`
- `propose_upgrade`
- `approve_upgrade`
- proposal status transitions to `Approved`

This ensures governance behavior is consistent across contracts using shared module logic.

### 4. Token-Backed Fee Flow Testing

Use a minimal mock token contract exposing `balance` and `transfer` so the shared `FeeManager` can execute real fee collection logic during trading integration tests.

### 5. Replay Protection Testing

When testing replay protection across contracts:

- Send the same message twice with identical parameters and verify the second is rejected.
- Use `try_*` methods to assert recoverable errors for replay attempts.
- Verify that different nonces with the same payload are accepted independently.

### 6. Cross-Chain Message Hash Verification

For contracts that compute message hashes:

- Verify hash determinism: the same inputs always produce the same hash.
- Verify hash uniqueness: different nonces produce different hashes.
- Use the public hash computation method to validate off-chain hash matching.

### 7. Fee Accounting Determinism

When testing fee collection across contracts:

- Set fees via admin functions before processing messages.
- Assert that fee accounting state is updated correctly after each message.
- Verify that zero-fee configurations still allow message processing.
- Ensure fee accounting is independent of other contract state.

### 8. Malformed Payload Handling

Test edge cases for message payloads:

- Empty payloads: verify acceptance or rejection per contract design.
- Oversized payloads: verify bounds enforcement.
- Boundary values: test at exact limits.

## Running Integration Tests

From the Contracts workspace root:

- `cargo test -p integration-tests`
- `cargo test --all`

## CI/CD Notes

The integration test crate is a workspace member, so it is executed by the existing CI test command.
The crate library remains minimal and `no_std`, while integration scenarios live under the tests directory.
