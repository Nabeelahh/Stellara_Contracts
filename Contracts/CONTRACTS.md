# Stellara Smart Contracts - Detailed Documentation

## Contract Architecture

All contracts follow Soroban best practices and are optimized for the Testnet environment.

### Design Patterns

1. **Contract Initialization**: All contracts require explicit initialization before use
2. **Authentication**: Functions requiring authorization use `require_auth()` for security
3. **Data Storage**: Persistent state stored in contract instance storage
4. **Error Handling**: Using Symbol-based error codes for gas efficiency
5. **Fee Handling**: Standardized fee collection via `FeeManager`

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
