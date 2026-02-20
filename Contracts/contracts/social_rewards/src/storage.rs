//! Optimized storage module for Social Rewards Contract
//!
//! Storage optimizations:
//! - Instance storage for admin, token, and stats (frequent reads, rare writes)
//! - Persistent storage for individual rewards with indexed access
//! - User reward index for efficient lookups
//! - Lazy loading patterns to reduce storage access

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec, symbol_short};

/// Contract version for migration tracking
const CONTRACT_VERSION: u32 = 2;

/// Optimized reward statistics - stored in instance storage
#[contracttype]
#[derive(Clone, Debug, Default)]
pub struct OptimizedRewardStats {
    pub total_rewards: u64,
    pub total_amount: i128,
    pub total_claimed: i128,
    pub last_reward_id: u64,
}

/// Optimized reward record - packed for efficient storage
#[contracttype]
#[derive(Clone, Debug)]
pub struct OptimizedReward {
    pub id: u64,
    pub user: Address,
    pub amount: i128,
    pub reward_type: Symbol,
    pub reason: Symbol,
    pub granted_by: Address,
    pub granted_at: u64,
    pub claimed: bool,
    pub claimed_at: u64,
}

/// Storage keys using enum for type safety and efficiency
#[contracttype]
#[derive(Clone, Debug)]
pub enum SocialRewardsDataKey {
    Init,
    Admin,
    Token,
    Stats,
    Reward(u64),              // Individual reward by ID
    UserRewardIds(Address),   // List of reward IDs for a user
    UnclaimedIndex,           // Index of unclaimed rewards for batch processing
}

/// Storage manager for social rewards contract
pub struct SocialRewardsStorage;

impl SocialRewardsStorage {
    // ============ Initialization ============
    
    pub fn is_initialized(env: &Env) -> bool {
        env.storage().instance().has(&SocialRewardsDataKey::Init)
    }
    
    pub fn set_initialized(env: &Env) {
        env.storage().instance().set(&SocialRewardsDataKey::Init, &true);
        let stats = OptimizedRewardStats {
            total_rewards: 0,
            total_amount: 0,
            total_claimed: 0,
            last_reward_id: 0,
        };
        env.storage().instance().set(&SocialRewardsDataKey::Stats, &stats);
    }
    
    // ============ Version Management ============
    
    pub fn get_version(env: &Env) -> u32 {
        env.storage().instance().get(&Symbol::new(env, "version")).unwrap_or(0)
    }
    
    pub fn set_version(env: &Env, version: u32) {
        env.storage().instance().set(&Symbol::new(env, "version"), &version);
    }
    
    // ============ Admin & Token ============
    
    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().instance().set(&SocialRewardsDataKey::Admin, admin);
    }
    
    pub fn get_admin(env: &Env) -> Option<Address> {
        env.storage().instance().get(&SocialRewardsDataKey::Admin)
    }
    
    pub fn set_token(env: &Env, token: &Address) {
        env.storage().instance().set(&SocialRewardsDataKey::Token, token);
    }
    
    pub fn get_token(env: &Env) -> Option<Address> {
        env.storage().instance().get(&SocialRewardsDataKey::Token)
    }
    
    // ============ Statistics ============
    
    pub fn get_stats(env: &Env) -> OptimizedRewardStats {
        env.storage().instance().get(&SocialRewardsDataKey::Stats).unwrap_or(OptimizedRewardStats {
            total_rewards: 0,
            total_amount: 0,
            total_claimed: 0,
            last_reward_id: 0,
        })
    }
    
    pub fn set_stats(env: &Env, stats: &OptimizedRewardStats) {
        env.storage().instance().set(&SocialRewardsDataKey::Stats, stats);
    }
    
    /// Increment stats when adding a reward - returns the new reward ID
    pub fn increment_reward_stats(env: &Env, amount: i128) -> u64 {
        let mut stats = Self::get_stats(env);
        stats.last_reward_id += 1;
        stats.total_rewards += 1;
        stats.total_amount += amount;
        Self::set_stats(env, &stats);
        stats.last_reward_id
    }
    
    /// Update stats when claiming a reward
    pub fn record_claim(env: &Env, amount: i128) {
        let mut stats = Self::get_stats(env);
        stats.total_claimed += amount;
        Self::set_stats(env, &stats);
    }
    
    // ============ Reward Storage ============
    
    /// Store individual reward with optimized key
    pub fn set_reward(env: &Env, reward: &OptimizedReward) {
        let key = SocialRewardsDataKey::Reward(reward.id);
        env.storage().persistent().set(&key, reward);
        
        // Update user's reward index
        Self::add_reward_to_user_index(env, &reward.user, reward.id);
        
        // Update unclaimed index if not claimed
        if !reward.claimed {
            Self::add_to_unclaimed_index(env, reward.id);
        }
    }
    
    /// Get reward by ID
    pub fn get_reward(env: &Env, reward_id: u64) -> Option<OptimizedReward> {
        env.storage().persistent().get(&SocialRewardsDataKey::Reward(reward_id))
    }
    
    /// Check if reward exists
    #[allow(dead_code)]
    pub fn has_reward(env: &Env, reward_id: u64) -> bool {
        env.storage().persistent().has(&SocialRewardsDataKey::Reward(reward_id))
    }
    
    /// Update reward (for claim status changes)
    pub fn update_reward(env: &Env, reward: &OptimizedReward) {
        let key = SocialRewardsDataKey::Reward(reward.id);
        env.storage().persistent().set(&key, reward);
        
        // Remove from unclaimed index if now claimed
        if reward.claimed {
            Self::remove_from_unclaimed_index(env, reward.id);
        }
    }
    
    // ============ User Index ============
    
    /// Add reward ID to user's index
    fn add_reward_to_user_index(env: &Env, user: &Address, reward_id: u64) {
        let key = SocialRewardsDataKey::UserRewardIds(user.clone());
        let mut reward_ids: Vec<u64> = env.storage().persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        reward_ids.push_back(reward_id);
        env.storage().persistent().set(&key, &reward_ids);
    }
    
    /// Get all reward IDs for a user
    pub fn get_user_reward_ids(env: &Env, user: &Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&SocialRewardsDataKey::UserRewardIds(user.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }
    
    /// Get rewards for a user (lazy loading)
    pub fn get_user_rewards(env: &Env, user: &Address) -> Vec<OptimizedReward> {
        let reward_ids = Self::get_user_reward_ids(env, user);
        let mut rewards = Vec::new(env);
        
        for reward_id in reward_ids.iter() {
            if let Some(reward) = Self::get_reward(env, reward_id) {
                rewards.push_back(reward);
            }
        }
        
        rewards
    }
    
    /// Get pending (unclaimed) rewards for a user with lazy loading
    #[allow(dead_code)]
    pub fn get_user_pending_rewards(env: &Env, user: &Address) -> Vec<OptimizedReward> {
        let reward_ids = Self::get_user_reward_ids(env, user);
        let mut pending = Vec::new(env);
        
        for reward_id in reward_ids.iter() {
            if let Some(reward) = Self::get_reward(env, reward_id) {
                if !reward.claimed {
                    pending.push_back(reward);
                }
            }
        }
        
        pending
    }
    
    /// Calculate pending rewards total for a user
    pub fn get_pending_rewards_total(env: &Env, user: &Address) -> i128 {
        let reward_ids = Self::get_user_reward_ids(env, user);
        let mut total: i128 = 0;
        
        for reward_id in reward_ids.iter() {
            if let Some(reward) = Self::get_reward(env, reward_id) {
                if !reward.claimed {
                    total += reward.amount;
                }
            }
        }
        
        total
    }
    
    // ============ Unclaimed Index ============
    
    /// Add reward to unclaimed index for batch processing
    fn add_to_unclaimed_index(env: &Env, reward_id: u64) {
        let mut unclaimed: Vec<u64> = env.storage().persistent()
            .get(&SocialRewardsDataKey::UnclaimedIndex)
            .unwrap_or_else(|| Vec::new(env));
        unclaimed.push_back(reward_id);
        env.storage().persistent().set(&SocialRewardsDataKey::UnclaimedIndex, &unclaimed);
    }
    
    /// Remove reward from unclaimed index
    fn remove_from_unclaimed_index(env: &Env, reward_id: u64) {
        let unclaimed: Vec<u64> = env.storage().persistent()
            .get(&SocialRewardsDataKey::UnclaimedIndex)
            .unwrap_or_else(|| Vec::new(env));
        
        let mut new_unclaimed = Vec::new(env);
        for id in unclaimed.iter() {
            if id != reward_id {
                new_unclaimed.push_back(id);
            }
        }
        
        env.storage().persistent().set(&SocialRewardsDataKey::UnclaimedIndex, &new_unclaimed);
    }
    
    /// Get all unclaimed reward IDs (for admin batch operations)
    pub fn get_unclaimed_reward_ids(env: &Env) -> Vec<u64> {
        env.storage().persistent()
            .get(&SocialRewardsDataKey::UnclaimedIndex)
            .unwrap_or_else(|| Vec::new(env))
    }
    
    // ============ Batch Operations ============
    
    /// Batch set rewards - more efficient for bulk operations
    #[allow(dead_code)]
    pub fn batch_set_rewards(env: &Env, rewards: &[OptimizedReward]) {
        for reward in rewards.iter() {
            Self::set_reward(env, reward);
        }
    }
    
    /// Batch update rewards
    #[allow(dead_code)]
    pub fn batch_update_rewards(env: &Env, rewards: &[OptimizedReward]) {
        for reward in rewards.iter() {
            Self::update_reward(env, reward);
        }
    }
    
    // ============ Migration Support ============
    
    /// Check if migration is needed
    #[allow(dead_code)]
    pub fn needs_migration(env: &Env) -> bool {
        Self::get_version(env) < CONTRACT_VERSION
    }
    
    /// Perform storage migration
    pub fn migrate_storage(env: &Env) -> u64 {
        let current_version = Self::get_version(env);
        
        if current_version == 0 {
            // First initialization
            Self::set_version(env, CONTRACT_VERSION);
            0
        } else if current_version == 1 {
            // Migrate from v1 to v2
            // Migrate legacy data format
            let migrated = Self::migrate_from_legacy(env);
            Self::set_version(env, CONTRACT_VERSION);
            migrated
        } else {
            0
        }
    }
    
    fn migrate_from_legacy(env: &Env) -> u64 {
        let mut migrated = 0u64;
        
        // Migrate admin
        let legacy_admin_key = symbol_short!("admin");
        if let Some(admin) = env.storage().persistent().get::<_, Address>(&legacy_admin_key) {
            Self::set_admin(env, &admin);
            migrated += 1;
        }
        
        // Migrate token
        let legacy_token_key = symbol_short!("token");
        if let Some(token) = env.storage().persistent().get::<_, Address>(&legacy_token_key) {
            Self::set_token(env, &token);
            migrated += 1;
        }
        
        // Migrate stats
        let legacy_stats_key = symbol_short!("stats");
        if let Some(legacy_stats) = env.storage().persistent().get::<_, OptimizedRewardStats>(&legacy_stats_key) {
            Self::set_stats(env, &legacy_stats);
            migrated += 1;
        }
        
        migrated
    }
    
    /// Check if legacy data exists
    pub fn has_legacy_data(env: &Env) -> bool {
        env.storage().persistent().has(&symbol_short!("admin")) ||
        env.storage().persistent().has(&symbol_short!("token")) ||
        env.storage().persistent().has(&symbol_short!("stats"))
    }
    
    // ============ Storage Statistics ============
    
    /// Get storage statistics for monitoring
    pub fn get_storage_stats(env: &Env) -> (u64, u64, u64) {
        let stats = Self::get_stats(env);
        let unclaimed_count = Self::get_unclaimed_reward_ids(env).len() as u64;
        (stats.total_rewards, unclaimed_count, stats.last_reward_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_data_key_variants() {
        // Test that data keys can be created and are distinct
        let key1 = SocialRewardsDataKey::Init;
        let key2 = SocialRewardsDataKey::Stats;
        let key3 = SocialRewardsDataKey::Reward(1);
        
        // Just verify they compile and are different variants
        match key1 {
            SocialRewardsDataKey::Init => (),
            _ => panic!("Expected Init"),
        }
        
        match key2 {
            SocialRewardsDataKey::Stats => (),
            _ => panic!("Expected Stats"),
        }
        
        match key3 {
            SocialRewardsDataKey::Reward(id) => assert_eq!(id, 1),
            _ => panic!("Expected Reward"),
        }
    }
}
