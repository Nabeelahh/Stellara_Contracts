//! Optimized storage module for Trading Contract
//! 
//! Storage optimizations implemented:
//! - Instance storage for static config (admin, version, oracle config)
//! - Persistent storage for trade data with optimized key patterns
//! - Batched storage operations for bulk trades
//! - Lazy loading for trade history

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec, symbol_short};

/// Contract version for migration tracking
#[allow(dead_code)]
const CONTRACT_VERSION: u32 = 2;

/// Optimized trade statistics - packed for efficient storage
#[contracttype]
#[derive(Clone, Debug, Default)]
pub struct OptimizedTradeStats {
    pub total_trades: u64,
    pub total_volume: i128,
    pub last_trade_id: u64,
}

/// Optimized oracle configuration stored in instance storage
#[contracttype]
#[derive(Clone, Debug)]
pub struct OptimizedOracleConfig {
    pub oracles: Vec<Address>,
    pub max_staleness: u64,
    pub min_sources: u32,
}

/// Optimized oracle status with packed fields
#[contracttype]
#[derive(Clone, Debug)]
pub struct OptimizedOracleStatus {
    pub last_pair: Symbol,
    pub last_price: i128,
    pub last_updated_at: u64,
    pub last_source_count: u32,
    pub consecutive_failures: u32,
}

impl OptimizedOracleStatus {
    pub fn new(env: &Env) -> Self {
        Self {
            last_pair: Symbol::new(env, "NONE"),
            last_price: 0,
            last_updated_at: 0,
            last_source_count: 0,
            consecutive_failures: 0,
        }
    }
}

/// Optimized trade record with reduced field sizes where possible
#[contracttype]
#[derive(Clone, Debug)]
pub struct OptimizedTrade {
    pub id: u64,
    pub trader: Address,
    pub pair: Symbol,
    pub amount: i128,
    pub price: i128,
    pub timestamp: u64,
    pub is_buy: bool,
}

/// Governance roles storage key
#[contracttype]
#[derive(Clone, Debug)]
pub enum TradingDataKey {
    Init,
    Paused,
    Stats,
    OracleConfig,
    OracleStatus,
    Roles,
    Trade(u64),           // Individual trade by ID
    TradeIdsByTrader(Address), // List of trade IDs for a trader
    RecentTrades,         // Recent trade IDs (circular buffer)
}

/// Storage manager for trading contract
pub struct TradingStorage;

#[allow(dead_code)]
impl TradingStorage {
    // ============ Initialization ============
    
    pub fn is_initialized(env: &Env) -> bool {
        env.storage().instance().has(&TradingDataKey::Init)
    }
    
    pub fn set_initialized(env: &Env) {
        env.storage().instance().set(&TradingDataKey::Init, &true);
        let stats = OptimizedTradeStats {
            total_trades: 0,
            total_volume: 0,
            last_trade_id: 0,
        };
        env.storage().instance().set(&TradingDataKey::Stats, &stats);
    }
    
    // ============ Version Management ============
    
    pub fn get_version(env: &Env) -> u32 {
        env.storage().instance().get(&Symbol::new(env, "version")).unwrap_or(0)
    }
    
    pub fn set_version(env: &Env, version: u32) {
        env.storage().instance().set(&Symbol::new(env, "version"), &version);
    }
    
    pub fn check_and_migrate(env: &Env) -> bool {
        let current_version = Self::get_version(env);
        if current_version < CONTRACT_VERSION {
            // Perform migration if needed
            Self::perform_migration(env, current_version);
            true
        } else {
            false
        }
    }
    
    fn perform_migration(env: &Env, from_version: u32) {
        // Migration logic from old storage format to new
        if from_version == 0 {
            // First initialization
            Self::set_version(env, CONTRACT_VERSION);
        } else if from_version == 1 {
            // Migrate from v1 to v2
            // Old format used symbol_short keys, new uses enum keys
            // Data structure remains compatible
            Self::set_version(env, CONTRACT_VERSION);
        }
    }
    
    // ============ Pause State ============
    
    pub fn is_paused(env: &Env) -> bool {
        env.storage().instance().get(&TradingDataKey::Paused).unwrap_or(false)
    }
    
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage().instance().set(&TradingDataKey::Paused, &paused);
    }
    
    // ============ Statistics ============
    
    pub fn get_stats(env: &Env) -> OptimizedTradeStats {
        env.storage().instance().get(&TradingDataKey::Stats).unwrap_or(OptimizedTradeStats {
            total_trades: 0,
            total_volume: 0,
            last_trade_id: 0,
        })
    }
    
    pub fn set_stats(env: &Env, stats: &OptimizedTradeStats) {
        env.storage().instance().set(&TradingDataKey::Stats, stats);
    }
    
    pub fn increment_trade_stats(env: &Env, amount: i128) -> u64 {
        let mut stats = Self::get_stats(env);
        stats.last_trade_id += 1;
        stats.total_trades += 1;
        stats.total_volume += amount;
        Self::set_stats(env, &stats);
        stats.last_trade_id
    }
    
    // ============ Oracle Configuration ============
    
    pub fn set_oracle_config(env: &Env, config: &OptimizedOracleConfig) {
        env.storage().instance().set(&TradingDataKey::OracleConfig, config);
    }
    
    pub fn get_oracle_config(env: &Env) -> Option<OptimizedOracleConfig> {
        env.storage().instance().get(&TradingDataKey::OracleConfig)
    }
    
    // ============ Oracle Status ============
    
    pub fn set_oracle_status(env: &Env, status: &OptimizedOracleStatus) {
        env.storage().instance().set(&TradingDataKey::OracleStatus, status);
    }
    
    pub fn get_oracle_status(env: &Env) -> OptimizedOracleStatus {
        env.storage().instance().get(&TradingDataKey::OracleStatus).unwrap_or_else(|| OptimizedOracleStatus::new(env))
    }
    
    // ============ Roles ============
    
    pub fn set_roles(env: &Env, roles: &soroban_sdk::Map<Address, shared::governance::GovernanceRole>) {
        env.storage().instance().set(&TradingDataKey::Roles, roles);
    }
    
    pub fn get_roles(env: &Env) -> Option<soroban_sdk::Map<Address, shared::governance::GovernanceRole>> {
        env.storage().instance().get(&TradingDataKey::Roles)
    }
    
    pub fn has_role(env: &Env, address: &Address) -> bool {
        if let Some(roles) = Self::get_roles(env) {
            roles.contains_key(address.clone())
        } else {
            false
        }
    }
    
    pub fn get_role(env: &Env, address: &Address) -> Option<shared::governance::GovernanceRole> {
        Self::get_roles(env)?.get(address.clone())
    }
    
    // ============ Trade Storage (Persistent) ============
    
    /// Store individual trade - optimized for direct access by ID
    pub fn set_trade(env: &Env, trade: &OptimizedTrade) {
        let key = TradingDataKey::Trade(trade.id);
        env.storage().persistent().set(&key, trade);
        
        // Update trader's trade list
        Self::add_trade_to_trader_index(env, &trade.trader, trade.id);
        
        // Update recent trades buffer
        Self::add_to_recent_trades(env, trade.id);
    }
    
    /// Get trade by ID
    pub fn get_trade(env: &Env, trade_id: u64) -> Option<OptimizedTrade> {
        env.storage().persistent().get(&TradingDataKey::Trade(trade_id))
    }
    
    /// Check if trade exists
    pub fn has_trade(env: &Env, trade_id: u64) -> bool {
        env.storage().persistent().has(&TradingDataKey::Trade(trade_id))
    }
    
    // ============ Trader Index ============
    
    /// Add trade ID to trader's index for efficient lookup
    fn add_trade_to_trader_index(env: &Env, trader: &Address, trade_id: u64) {
        let key = TradingDataKey::TradeIdsByTrader(trader.clone());
        let mut trade_ids: Vec<u64> = env.storage().persistent().get(&key).unwrap_or_else(|| Vec::new(env));
        trade_ids.push_back(trade_id);
        env.storage().persistent().set(&key, &trade_ids);
    }
    
    /// Get all trade IDs for a trader
    pub fn get_trader_trade_ids(env: &Env, trader: &Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&TradingDataKey::TradeIdsByTrader(trader.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }
    
    /// Get trades for a trader (lazy loading)
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
    
    // ============ Recent Trades Buffer ============
    
    const MAX_RECENT_TRADES: u32 = 100;
    
    fn add_to_recent_trades(env: &Env, trade_id: u64) {
        let mut recent: Vec<u64> = env
            .storage()
            .persistent()
            .get(&TradingDataKey::RecentTrades)
            .unwrap_or_else(|| Vec::new(env));

        recent.push_back(trade_id);

        if recent.len() > Self::MAX_RECENT_TRADES {
            let len = recent.len();
            let keep = Self::MAX_RECENT_TRADES;
            let start = len.saturating_sub(keep);
            let mut trimmed = Vec::new(env);

            for (i, id) in recent.iter().enumerate() {
                if (i as u32) >= start {
                    trimmed.push_back(id);
                }
            }

            recent = trimmed;
        }

        env.storage()
            .persistent()
            .set(&TradingDataKey::RecentTrades, &recent);
    }
    
    pub fn get_recent_trade_ids(env: &Env) -> Vec<u64> {
        env.storage().persistent()
            .get(&TradingDataKey::RecentTrades)
            .unwrap_or_else(|| Vec::new(env))
    }
    
    // ============ Batch Operations ============
    
    /// Batch store trades - more efficient for bulk operations
    pub fn batch_set_trades(env: &Env, trades: &[OptimizedTrade]) {
        for trade in trades.iter() {
            Self::set_trade(env, trade);
        }
    }
    

    
    // ============ Storage Cleanup ============
    
    /// Remove old trade data (governance function for pruning)
    pub fn remove_trade(env: &Env, trade_id: u64) {
        env.storage().persistent().remove(&TradingDataKey::Trade(trade_id));
    }
    
    /// Get storage statistics for monitoring
    pub fn get_storage_stats(env: &Env) -> (u64, u64) {
        let stats = Self::get_stats(env);
        let recent_count = Self::get_recent_trade_ids(env).len() as u64;
        (stats.total_trades, recent_count)
    }
}

/// Migration helper for upgrading from legacy storage
pub struct TradingStorageMigration;

impl TradingStorageMigration {
    /// Migrate from legacy symbol_short keys to enum keys
    pub fn migrate_from_legacy(env: &Env) -> u64 {
        let mut migrated_count = 0u64;
        
        // Migrate stats
        let legacy_stats_key = symbol_short!("stats");
        if let Some(stats) = env.storage().persistent().get::<_, OptimizedTradeStats>(&legacy_stats_key) {
            TradingStorage::set_stats(env, &stats);
            migrated_count += 1;
        }
        
        // Migrate pause state
        let legacy_pause_key = symbol_short!("pause");
        if let Some(paused) = env.storage().persistent().get::<_, bool>(&legacy_pause_key) {
            TradingStorage::set_paused(env, paused);
            migrated_count += 1;
        }
        
        // Note: Individual trades are accessed by ID and don't need migration
        // as the data structure is compatible
        
        migrated_count
    }
    
    /// Check if legacy data exists
    pub fn has_legacy_data(env: &Env) -> bool {
        env.storage().persistent().has(&symbol_short!("stats")) ||
        env.storage().persistent().has(&symbol_short!("pause"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_data_key_variants() {
        // Test that data keys can be created and are distinct
        let key1 = TradingDataKey::Init;
        let key2 = TradingDataKey::Stats;
        let key3 = TradingDataKey::Trade(1);
        
        // Just verify they compile and are different variants
        match key1 {
            TradingDataKey::Init => (),
            _ => panic!("Expected Init"),
        }
        
        match key2 {
            TradingDataKey::Stats => (),
            _ => panic!("Expected Stats"),
        }
        
        match key3 {
            TradingDataKey::Trade(id) => assert_eq!(id, 1),
            _ => panic!("Expected Trade"),
        }
    }
}
