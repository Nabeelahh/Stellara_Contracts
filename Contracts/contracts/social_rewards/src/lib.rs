#![no_std]
#![allow(unexpected_cfgs)]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};
use shared::events::{EventEmitter, RewardAddedEvent, RewardClaimedEvent};

mod storage;
use storage::{SocialRewardsStorage, OptimizedRewardStats, OptimizedReward};

/// Social reward record
#[contracttype]
#[derive(Clone, Debug)]
pub struct Reward {
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

/// Batch reward request
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRewardRequest {
    pub user: Address,
    pub amount: i128,
    pub reward_type: Symbol,
    pub reason: Symbol,
}

/// Batch reward result
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRewardResult {
    pub reward_id: Option<u64>,
    pub success: bool,
    pub error_code: Option<u32>,
}

/// Batch claim request
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRewardClaimRequest {
    pub reward_id: u64,
    pub user: Address,
}

/// Batch claim result
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchRewardClaimResult {
    pub reward_id: u64,
    pub amount_claimed: Option<i128>,
    pub success: bool,
    pub error_code: Option<u32>,
}

/// Batch reward operation result
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRewardOperation {
    pub successful_rewards: soroban_sdk::Vec<u64>,
    pub failed_rewards: soroban_sdk::Vec<BatchRewardResult>,
    pub total_amount_granted: i128,
    pub gas_saved: i128,
}

/// Social rewards statistics (re-exported from storage module)
pub type RewardStats = OptimizedRewardStats;

/// Social rewards error codes
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RewardError {
    Unauthorized = 5001,
    InvalidAmount = 5002,
    RewardNotFound = 5003,
    AlreadyClaimed = 5004,
    InsufficientBalance = 5005,
    NotInitialized = 5006,
    BatchSizeExceeded = 5007,
    BatchOperationFailed = 5008,
}

impl From<RewardError> for soroban_sdk::Error {
    fn from(error: RewardError) -> Self {
        soroban_sdk::Error::from_contract_error(error as u32)
    }
}

impl From<&RewardError> for soroban_sdk::Error {
    fn from(error: &RewardError) -> Self {
        soroban_sdk::Error::from_contract_error(*error as u32)
    }
}

impl From<soroban_sdk::Error> for RewardError {
    fn from(_error: soroban_sdk::Error) -> Self {
        RewardError::Unauthorized
    }
}

#[contract]
pub struct SocialRewardsContract;

#[contractimpl]
impl SocialRewardsContract {
    /// Initialize the contract with admin and reward token
    pub fn init(
        env: Env,
        admin: Address,
        reward_token: Address,
    ) -> Result<(), RewardError> {
        // Check if already initialized using optimized storage
        if SocialRewardsStorage::is_initialized(&env) {
            return Err(RewardError::Unauthorized);
        }

        // Set initialization flag
        SocialRewardsStorage::set_initialized(&env);

        // Store admin in instance storage (cheaper for static data)
        SocialRewardsStorage::set_admin(&env, &admin);

        // Store reward token in instance storage
        SocialRewardsStorage::set_token(&env, &reward_token);

        // Initialize stats in instance storage
        SocialRewardsStorage::set_stats(&env, &OptimizedRewardStats::default());

        Ok(())
    }
    
    /// Migrate storage from legacy format (admin only)
    pub fn migrate_storage(env: Env, admin: Address) -> Result<u64, RewardError> {
        admin.require_auth();
        
        // Verify admin
        let stored_admin = SocialRewardsStorage::get_admin(&env)
            .ok_or(RewardError::NotInitialized)?;
        if admin != stored_admin {
            return Err(RewardError::Unauthorized);
        }
        
        if !SocialRewardsStorage::has_legacy_data(&env) {
            return Ok(0);
        }
        
        let migrated = SocialRewardsStorage::migrate_storage(&env);
        Ok(migrated)
    }

    /// Add a reward for a user (admin only)
    pub fn add_reward(
        env: Env,
        admin: Address,
        user: Address,
        amount: i128,
        reward_type: Symbol,
        reason: Symbol,
    ) -> Result<u64, RewardError> {
        admin.require_auth();

        // Verify caller is admin using optimized storage
        let stored_admin = SocialRewardsStorage::get_admin(&env)
            .ok_or(RewardError::NotInitialized)?;
        if admin != stored_admin {
            return Err(RewardError::Unauthorized);
        }

        // Validate amount
        if amount <= 0 {
            return Err(RewardError::InvalidAmount);
        }

        // Get next reward ID using optimized storage
        let reward_id = SocialRewardsStorage::increment_reward_stats(&env, amount);
        let timestamp = env.ledger().timestamp();

        // Create reward record
        let reward = OptimizedReward {
            id: reward_id,
            user: user.clone(),
            amount,
            reward_type: reward_type.clone(),
            reason: reason.clone(),
            granted_by: admin.clone(),
            granted_at: timestamp,
            claimed: false,
            claimed_at: 0,
        };

        // Store reward with optimized individual key
        SocialRewardsStorage::set_reward(&env, &reward);

        // Emit reward added event
        EventEmitter::reward_added(&env, RewardAddedEvent {
            reward_id,
            user,
            amount,
            reward_type,
            reason,
            granted_by: admin,
            timestamp,
        });

        Ok(reward_id)
    }

    /// Add multiple rewards in a single transaction
    pub fn batch_add_reward(
        env: Env,
        admin: Address,
        requests: soroban_sdk::Vec<BatchRewardRequest>,
    ) -> Result<BatchRewardOperation, RewardError> {
        // Maximum batch size to prevent resource exhaustion
        const MAX_BATCH_SIZE: u32 = 30;
        
        if requests.len() > MAX_BATCH_SIZE {
            return Err(RewardError::BatchSizeExceeded);
        }

        // Verify caller is admin using optimized storage
        let stored_admin = SocialRewardsStorage::get_admin(&env)
            .ok_or(RewardError::NotInitialized)?;
        if admin != stored_admin {
            return Err(RewardError::Unauthorized);
        }

        let mut successful_rewards = soroban_sdk::Vec::new(&env);
        let mut failed_rewards = soroban_sdk::Vec::new(&env);
        let mut total_amount_granted = 0i128;
        let mut total_gas_saved = 0i128;

        // Get current stats from optimized storage
        let mut stats = SocialRewardsStorage::get_stats(&env);

        // Process each reward request
        for request in requests.iter() {
            let result = match Self::process_single_reward(
                &env,
                &request,
                &admin,
                &mut stats,
            ) {
                Ok(reward_id) => {
                    successful_rewards.push_back(reward_id);
                    total_amount_granted += request.amount;
                    total_gas_saved += 500i128; // Estimated gas savings per reward
                    BatchRewardResult {
                        reward_id: Some(reward_id),
                        success: true,
                        error_code: None,
                    }
                }
                Err(error) => BatchRewardResult {
                    reward_id: None,
                    success: false,
                    error_code: Some(error as u32),
                },
            };

            failed_rewards.push_back(result);
        }

        // Update stats in optimized storage
        SocialRewardsStorage::set_stats(&env, &stats);

        Ok(BatchRewardOperation {
            successful_rewards,
            failed_rewards,
            total_amount_granted,
            gas_saved: total_gas_saved,
        })
    }

    /// Process a single reward within a batch operation
    fn process_single_reward(
        env: &Env,
        request: &BatchRewardRequest,
        admin: &Address,
        stats: &mut OptimizedRewardStats,
    ) -> Result<u64, RewardError> {
        // Validate amount
        if request.amount <= 0 {
            return Err(RewardError::InvalidAmount);
        }

        // Get next reward ID
        let reward_id = stats.last_reward_id + 1;
        let timestamp = env.ledger().timestamp();

        // Create reward record
        let reward = OptimizedReward {
            id: reward_id,
            user: request.user.clone(),
            amount: request.amount,
            reward_type: request.reward_type.clone(),
            reason: request.reason.clone(),
            granted_by: admin.clone(),
            granted_at: timestamp,
            claimed: false,
            claimed_at: 0,
        };

        // Store reward with optimized storage
        SocialRewardsStorage::set_reward(env, &reward);

        // Update stats
        stats.total_rewards += 1;
        stats.total_amount += request.amount;
        stats.last_reward_id = reward_id;

        // Emit reward added event
        EventEmitter::reward_added(env, RewardAddedEvent {
            reward_id,
            user: request.user.clone(),
            amount: request.amount,
            reward_type: request.reward_type.clone(),
            reason: request.reason.clone(),
            granted_by: admin.clone(),
            timestamp,
        });

        Ok(reward_id)
    }

    /// Claim multiple rewards in a single transaction
    pub fn batch_claim_reward(
        env: Env,
        requests: soroban_sdk::Vec<BatchRewardClaimRequest>,
    ) -> Result<soroban_sdk::Vec<BatchRewardClaimResult>, RewardError> {
        // Maximum batch size to prevent resource exhaustion
        const MAX_BATCH_SIZE: u32 = 25;
        
        if requests.len() > MAX_BATCH_SIZE {
            return Err(RewardError::BatchSizeExceeded);
        }

        let mut results = soroban_sdk::Vec::new(&env);

        // Get reward token from optimized storage
        let token = SocialRewardsStorage::get_token(&env)
            .ok_or(RewardError::NotInitialized)?;
        let token_client = soroban_sdk::token::Client::new(&env, &token);

        // Get stats from optimized storage
        let mut stats = SocialRewardsStorage::get_stats(&env);

        // Process each claim request
        for request in requests.iter() {
            request.user.require_auth();

            let result = match Self::process_single_reward_claim(
                &env,
                &request,
                &mut stats,
                &token_client,
            ) {
                Ok(amount) => {
                    BatchRewardClaimResult {
                        reward_id: request.reward_id,
                        amount_claimed: Some(amount),
                        success: true,
                        error_code: None,
                    }
                }
                Err(error) => BatchRewardClaimResult {
                    reward_id: request.reward_id,
                    amount_claimed: None,
                    success: false,
                    error_code: Some(error as u32),
                },
            };

            results.push_back(result);
        }

        // Update stats in optimized storage
        SocialRewardsStorage::set_stats(&env, &stats);

        Ok(results)
    }

    /// Process a single reward claim within a batch operation
    fn process_single_reward_claim(
        env: &Env,
        request: &BatchRewardClaimRequest,
        stats: &mut OptimizedRewardStats,
        token_client: &soroban_sdk::token::Client,
    ) -> Result<i128, RewardError> {
        let mut reward = SocialRewardsStorage::get_reward(env, request.reward_id)
            .ok_or(RewardError::RewardNotFound)?;

        // Verify user owns the reward
        if reward.user != request.user {
            return Err(RewardError::Unauthorized);
        }

        // Check if already claimed
        if reward.claimed {
            return Err(RewardError::AlreadyClaimed);
        }

        // Check contract balance
        let balance = token_client.balance(&env.current_contract_address());
        if balance < reward.amount {
            return Err(RewardError::InsufficientBalance);
        }

        // Mark as claimed
        let timestamp = env.ledger().timestamp();
        reward.claimed = true;
        reward.claimed_at = timestamp;
        SocialRewardsStorage::update_reward(env, &reward);

        // Update stats
        stats.total_claimed += reward.amount;

        // Transfer tokens to user
        token_client.transfer(
            &env.current_contract_address(),
            &request.user,
            &reward.amount,
        );

        // Emit reward claimed event
        EventEmitter::reward_claimed(env, RewardClaimedEvent {
            reward_id: request.reward_id,
            user: request.user.clone(),
            amount: reward.amount,
            timestamp,
        });

        Ok(reward.amount)
    }

    /// Claim a reward
    pub fn claim_reward(
        env: Env,
        reward_id: u64,
        user: Address,
    ) -> Result<i128, RewardError> {
        user.require_auth();

        // Get reward from optimized storage
        let mut reward = SocialRewardsStorage::get_reward(&env, reward_id)
            .ok_or(RewardError::RewardNotFound)?;

        // Verify user owns the reward
        if reward.user != user {
            return Err(RewardError::Unauthorized);
        }

        // Check if already claimed
        if reward.claimed {
            return Err(RewardError::AlreadyClaimed);
        }

        // Get reward token from optimized storage
        let token = SocialRewardsStorage::get_token(&env)
            .ok_or(RewardError::NotInitialized)?;

        // Check contract balance
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());
        if balance < reward.amount {
            return Err(RewardError::InsufficientBalance);
        }

        // Mark as claimed
        let timestamp = env.ledger().timestamp();
        reward.claimed = true;
        reward.claimed_at = timestamp;
        SocialRewardsStorage::update_reward(&env, &reward);

        // Update stats
        SocialRewardsStorage::record_claim(&env, reward.amount);

        // Transfer tokens to user
        token_client.transfer(
            &env.current_contract_address(),
            &user,
            &reward.amount,
        );

        // Emit reward claimed event
        EventEmitter::reward_claimed(&env, RewardClaimedEvent {
            reward_id,
            user,
            amount: reward.amount,
            timestamp,
        });

        Ok(reward.amount)
    }

    /// Get a reward by ID
    pub fn get_reward(env: Env, reward_id: u64) -> Result<OptimizedReward, RewardError> {
        SocialRewardsStorage::get_reward(&env, reward_id)
            .ok_or(RewardError::RewardNotFound)
    }

    /// Get all reward IDs for a user
    pub fn get_user_rewards(env: Env, user: Address) -> soroban_sdk::Vec<u64> {
        SocialRewardsStorage::get_user_reward_ids(&env, &user)
    }
    
    /// Get all rewards for a user
    pub fn get_user_reward_details(env: Env, user: Address) -> soroban_sdk::Vec<OptimizedReward> {
        SocialRewardsStorage::get_user_rewards(&env, &user)
    }

    /// Get rewards statistics
    pub fn get_stats(env: Env) -> OptimizedRewardStats {
        SocialRewardsStorage::get_stats(&env)
    }

    /// Get contract info
    pub fn get_info(env: Env) -> Result<(Address, Address), RewardError> {
        let admin = SocialRewardsStorage::get_admin(&env)
            .ok_or(RewardError::NotInitialized)?;
        let token = SocialRewardsStorage::get_token(&env)
            .ok_or(RewardError::NotInitialized)?;
        Ok((admin, token))
    }

    /// Get pending (unclaimed) rewards total for a user
    pub fn get_pending_rewards(env: Env, user: Address) -> i128 {
        SocialRewardsStorage::get_pending_rewards_total(&env, &user)
    }
    
    /// Get storage statistics for monitoring
    pub fn get_storage_stats(env: Env) -> (u64, u64, u64) {
        SocialRewardsStorage::get_storage_stats(&env)
    }
}

#[cfg(test)]
mod test;
