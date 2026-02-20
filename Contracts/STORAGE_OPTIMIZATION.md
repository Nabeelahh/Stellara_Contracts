# Storage Optimization Implementation

## Overview

This document describes the storage optimization implementation for Stellara smart contracts. The optimizations reduce storage costs, improve access patterns, and provide migration strategies for existing data.

## Key Optimizations Implemented

### 1. Tiered Storage Usage

Soroban provides three storage types with different cost characteristics:

| Storage Type | Cost | TTL | Use Case |
|-------------|------|-----|----------|
| `instance()` | Lowest | Contract lifetime | Static config, admin, metadata |
| `persistent()` | Medium | Extended | User data, balances, records |
| `temporary()` | Lowest | Short | Cache, transient data |

#### Implementation

- **Instance Storage**: Used for admin addresses, token addresses, version info, stats, and configuration
- **Persistent Storage**: Used for individual records (trades, rewards, schedules) with indexed keys
- **Temporary Storage**: Available for future caching implementations

### 2. Optimized Key Patterns

#### Before (Legacy)
```rust
// Scattered string keys
let admin_key = symbol_short!("admin");
let stats_key = symbol_short!("stats");
let trades_key = symbol_short!("trades");
```

#### After (Optimized)
```rust
// Enum-based type-safe keys
#[contracttype]
pub enum TradingDataKey {
    Admin,
    Stats,
    Trade(u64),           // Individual trade by ID
    TradeIdsByTrader(Address), // Index for efficient lookup
}
```

**Benefits:**
- Type safety at compile time
- Smaller key sizes (enums vs strings)
- Clear data organization
- Easier migration tracking

### 3. Individual Record Storage vs Bulk Maps

#### Before (Legacy)
```rust
// Storing all trades in a single Map
let mut trades: Map<u64, Trade> = env.storage().persistent().get(&trades_key).unwrap_or_default();
trades.set(trade_id, trade);
env.storage().persistent().set(&trades_key, &trades); // Rewrite entire map
```

#### After (Optimized)
```rust
// Individual key per trade
let key = TradingDataKey::Trade(trade_id);
env.storage().persistent().set(&key, &trade); // Only write one record
```

**Benefits:**
- Reduced write amplification
- Better cache locality
- Easier partial updates
- Lower gas costs for individual operations

### 4. User Indexing for Efficient Queries

```rust
// Maintain per-user index for O(1) lookups
pub fn add_trade_to_trader_index(env: &Env, trader: &Address, trade_id: u64) {
    let key = TradingDataKey::TradeIdsByTrader(trader.clone());
    let mut trade_ids: Vec<u64> = env.storage().persistent().get(&key).unwrap_or_default();
    trade_ids.push_back(trade_id);
    env.storage().persistent().set(&key, &trade_ids);
}
```

### 5. Lazy Loading Patterns

```rust
// Load only needed data
pub fn get_trader_trades(env: &Env, trader: &Address) -> Vec<OptimizedTrade> {
    let trade_ids = Self::get_trader_trade_ids(env, trader);
    let mut trades = Vec::new(env);
    
    for trade_id in trade_ids.iter() {
        if let Some(trade) = Self::get_trade(env, trade_id) {
            trades.push_back(trade);
        }
    }
    trades
}
```

## Contracts Optimized

### 1. Trading Contract (`contracts/trading`)

**Changes:**
- Created `storage.rs` module with optimized storage patterns
- Migrated from `symbol_short!()` keys to enum-based `TradingDataKey`
- Moved admin, stats, oracle config to instance storage
- Individual trade storage with trader indexing
- Added recent trades buffer (circular buffer of last 100 trades) with optimized trimming to keep only the most recent entries in a single pass
- Migration support from v1 to v2

**Storage Keys:**
- `Init`, `Paused`, `Stats`, `OracleConfig`, `OracleStatus`, `Roles` → Instance
- `Trade(u64)`, `TradeIdsByTrader(Address)`, `RecentTrades` → Persistent

### 2. Social Rewards Contract (`contracts/social_rewards`)

**Changes:**
- Created `storage.rs` module with optimized storage patterns
- Migrated from `symbol_short!()` keys to enum-based `SocialRewardsDataKey`
- Moved admin, token, stats to instance storage
- Individual reward storage with user indexing
- Added unclaimed rewards index for batch operations
- Migration support from v1 to v2

**Storage Keys:**
- `Init`, `Admin`, `Token`, `Stats` → Instance
- `Reward(u64)`, `UserRewardIds(Address)`, `UnclaimedIndex` → Persistent

### 3. Academy Vesting Contract (`contracts/academy`)

**Changes:**
- Created `storage.rs` module with optimized storage patterns
- Migrated from `symbol_short!()` keys to enum-based `AcademyDataKey`
- Moved admin, token, governance, counter to instance storage
- Individual schedule storage with beneficiary indexing
- Added active schedules index for efficient querying
- Migration support from v1 to v2

**Storage Keys:**
- `Init`, `Admin`, `Token`, `Governance`, `Counter` → Instance
- `Schedule(u64)`, `UserScheduleIds(Address)`, `ActiveSchedules` → Persistent

### 4. Shared Storage Module (`shared/src/storage.rs`)

**Features:**
- `StoragePrefix` enum for standardized key prefixes
- `StorageKey` builder for constructing typed keys
- `OptimizedStorage` trait for consistent storage operations
- `MigrationManager` for version tracking and data migration
- `BatchStorage` for efficient bulk operations
- `StorageCostEstimator` for optimization analysis

## Migration Strategy

### Version Tracking

Each contract now tracks its storage version:

```rust
const CONTRACT_VERSION: u32 = 2;

pub fn migrate_storage(env: &Env) -> u64 {
    let current_version = Self::get_version(env);
    
    if current_version == 0 {
        // First initialization
        Self::set_version(env, CONTRACT_VERSION);
        0
    } else if current_version == 1 {
        // Migrate from v1 to v2
        let migrated = Self::migrate_from_legacy(env);
        Self::set_version(env, CONTRACT_VERSION);
        migrated
    } else {
        0
    }
}
```

### Migration Functions

Each contract provides:

1. **`migrate_storage(admin)`** - Admin function to trigger migration
2. **`has_legacy_data()`** - Check if legacy data exists
3. **`migrate_from_legacy()`** - Perform the actual data migration

### Migration Process

1. **Detect Legacy Data**: Check for old `symbol_short!()` keys
2. **Read Legacy Data**: Load data from old storage format
3. **Write to New Storage**: Store in optimized format
4. **Update Version**: Mark migration complete
5. **Clean Up** (optional): Remove old data to reclaim storage

## Cost Savings Analysis

### Instance vs Persistent Storage

| Data Type | Old Location | New Location | Est. Savings |
|-----------|-------------|--------------|--------------|
| Admin address | Persistent | Instance | ~90% |
| Token address | Persistent | Instance | ~90% |
| Stats | Persistent | Instance | ~90% |
| Config | Persistent | Instance | ~90% |

### Key Size Optimization

| Key Type | Old Size | New Size | Savings |
|----------|----------|----------|---------|
| Admin | ~10 bytes | ~4 bytes | ~60% |
| Stats | ~10 bytes | ~4 bytes | ~60% |
| Trade ID | ~10 bytes | ~8 bytes | ~20% |

### Write Amplification Reduction

| Operation | Before | After | Improvement |
|-----------|--------|-------|-------------|
| Add Trade | O(n) - rewrite all | O(1) - single write | ~n x |
| Update Reward | O(n) - rewrite all | O(1) - single write | ~n x |
| Claim Schedule | O(n) - rewrite all | O(1) - single write | ~n x |

## Backward Compatibility

### Type Aliases

For backward compatibility, type aliases are provided:

```rust
// In trading/src/lib.rs
pub type TradeStats = OptimizedTradeStats;
pub type OracleConfig = OptimizedOracleConfig;
pub type OracleStatus = OptimizedOracleStatus;
```

### API Compatibility

All existing public functions maintain their signatures:
- `get_stats()` returns same type (via alias)
- `get_reward()` returns same type (via alias)
- `get_vesting()` returns same type (via alias)

## Testing

Each storage module includes unit tests:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_initialization() { ... }
    
    #[test]
    fn test_trade_storage() { ... }
    
    #[test]
    fn test_migration() { ... }
}
```

Run tests with:
```bash
cd Contracts
cargo test --package trading
cargo test --package social_rewards
cargo test --package academy
```

## Future Optimizations

1. **Temporary Storage Cache**: Use `temporary()` storage for frequently accessed computed values
2. **Batch Operations**: Further optimize bulk operations with parallel processing
3. **Storage Pruning**: Implement automatic cleanup of old/irrelevant data
4. **Compression**: Consider data compression for large structures
5. **Event-Driven Indexing**: Off-load indexing to event consumers

## Security Considerations

1. **Migration Authorization**: Only admin can trigger migrations
2. **Version Validation**: Contracts check version compatibility
3. **Data Integrity**: Migration preserves all existing data
4. **Atomic Operations**: Critical updates are atomic

## References

- [Soroban Storage Documentation](https://soroban.stellar.org/docs/fundamentals-and-concepts/persisting-data)
- [Stellar Smart Contract Best Practices](https://soroban.stellar.org/docs/learn/best-practices)
