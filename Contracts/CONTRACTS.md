# Stellara Smart Contracts - Detailed Documentation

## Contract Architecture

All contracts follow Soroban best practices and are optimized for the Testnet environment.

### Design Patterns

1. **Contract Initialization**: All contracts require explicit initialization before use
2. **Authentication**: Functions requiring authorization use `require_auth()` for security
3. **Data Storage**: Persistent state stored in contract instance storage
4. **Error Handling**: Using Symbol-based error codes for gas efficiency
5. **Fee Handling**: Standardized fee collection via `FeeManager`
6. **Cross-Contract Safety**: Atomic multi-contract operations via `safe_call`

## Cross-Contract Call Safety

The system implements a `CrossCall` module (`shared/src/safe_call.rs`) to ensure atomicity and proper error propagation when contracts call each other.

### Guarantees
1.  **Atomicity**: If a downstream contract call fails (panics or returns error), the upstream contract catches the error and propagates it, causing the entire transaction (including any prior state changes like fee payments) to roll back.
2.  **Defensive Checks**: The `safe_invoke` wrapper abstracts `env.try_invoke_contract`, ensuring that all cross-contract calls are handled safely.

### Usage
Use `shared::safe_call::safe_invoke` instead of raw `env.invoke_contract` when you need to handle potential failures gracefully or ensure explicit error codes are returned.

```rust
match safe_invoke(&env, &contract_id, &func_name, args) {
    Ok(val) => { /* success */ },
    Err(code) => { /* handle error or propagate */ }
}
```

## Fee Handling

All contracts implementing fee collection use the `FeeManager` from the shared library.

### Fee Collection Process
1. **Check Balance**: The contract verifies the payer has sufficient balance of the fee token.
2. **Collect Fee**: The fee is transferred from the payer to the designated fee recipient.
3. **Execute Operation**: If fee collection succeeds, the contract operation proceeds.

### Error Codes
- `InsufficientBalance` (1001): The payer does not have enough funds to cover the fee.
- `InvalidAmount` (1002): The fee amount is invalid (negative).

## Trading Contract

### Purpose
Enables decentralized exchange of cryptocurrency pairs with trade history tracking.

### State Variables
- `stats`: TradeStats - Global trading statistics
- `trades`: Vec<Trade> - Complete trade history

### Key Structs

```rust
pub struct Trade {
    pub id: u64,
    pub trader: Address,
    pub pair: Symbol,          // e.g., "USDT" 
    pub amount: i128,          // Amount being traded
    pub price: i128,           // Price per unit
    pub timestamp: u64,        // Ledger timestamp
    pub is_buy: bool,          // Buy vs Sell order
}

pub struct TradeStats {
    pub total_trades: u64,
    pub total_volume: i128,
    pub last_trade_id: u64,
}

## Staking Rewards Contract

### Purpose
Allows users to stake tokens in different pools to earn rewards from protocol revenue.

### Pools
- **30 Days**: 5.00% APY
- **60 Days**: 10.00% APY
- **90 Days**: 15.00% APY

### Features
- **Early Withdrawal Penalty**: 10% deduction from principal if withdrawn before the lockup period ends.
- **Auto-compounding**: Users can re-stake their earned rewards into their principal.
- **Reward Claiming**: Separate function to withdraw rewards without affecting the stake.

### Key Structs

```rust
pub struct UserStake {
    pub amount: i128,              // Staked amount
    pub pool_id: u32,             // 0=30d, 1=60d, 2=90d
    pub start_timestamp: u64,      // Initial staking time
    pub last_claim_timestamp: u64, // Last time rewards were claimed
}

pub struct PoolConfig {
    pub lockup_seconds: u64,
    pub apy_bps: u32,              // APY in basis points (100 = 1%)
}
```
