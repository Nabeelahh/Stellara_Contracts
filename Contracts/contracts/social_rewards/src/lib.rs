#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

#[contract]
pub struct SocialRewardsContract;

/// Engagement record for tracking social activities
#[contracttype]
#[derive(Clone, Debug)]
pub struct Engagement {
    pub id: u64,
    pub user: Address,
    pub engagement_type: Symbol,
    pub timestamp: u64,
    pub metadata: i128,
}

/// Event emitted when engagement is recorded
#[contracttype]
#[derive(Clone, Debug)]
pub struct EngagementRecorded {
    pub engagement_id: u64,
    pub user: Address,
    pub engagement_type: Symbol,
    pub timestamp: u64,
    pub metadata: i128,
}

/// Event emitted when reward is distributed
#[contracttype]
#[derive(Clone, Debug)]
pub struct RewardDistributed {
    pub engagement_id: u64,
    pub user: Address,
    pub reward_amount: i128,
    pub timestamp: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RewardError {
    InvalidAmount = 5001,
    NotInitialized = 5002,
    Unauthorized = 5003,
    InsufficientBalance = 5004,
    EngagementNotFound = 5005,
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

#[contractimpl]
impl SocialRewardsContract {
    /// Initialize the social rewards contract
    pub fn init(env: Env, admin: Address) -> Result<(), RewardError> {
        let init_key = symbol_short!("init");
        if env.storage().persistent().has(&init_key) {
            return Err(RewardError::Unauthorized);
        }

        env.storage().persistent().set(&init_key, &true);
        env.storage()
            .persistent()
            .set(&symbol_short!("admin"), &admin);
        env.storage()
            .persistent()
            .set(&symbol_short!("eng_cnt"), &0u64);

        Ok(())
    }

    /// Record an engagement activity
    pub fn record_engagement(
        env: Env,
        user: Address,
        engagement_type: Symbol,
        metadata: i128,
    ) -> Result<u64, RewardError> {
        let init_key = symbol_short!("init");
        if !env.storage().persistent().has(&init_key) {
            return Err(RewardError::NotInitialized);
        }

        if metadata < 0 {
            return Err(RewardError::InvalidAmount);
        }

        let current_timestamp = env.ledger().timestamp();

        // Get next engagement ID
        let counter_key = symbol_short!("eng_cnt");
        let engagement_id: u64 = env.storage().persistent().get(&counter_key).unwrap_or(0u64);
        let next_id = engagement_id + 1;

        // Create engagement record
        let engagement = Engagement {
            id: next_id,
            user: user.clone(),
            engagement_type: engagement_type.clone(),
            timestamp: current_timestamp,
            metadata,
        };

        // Store engagement
        let engagement_key = (symbol_short!("eng"), next_id);
        env.storage().persistent().set(&engagement_key, &engagement);

        // Update counter
        env.storage().persistent().set(&counter_key, &next_id);

        // Emit EngagementRecorded event
        let engagement_event = EngagementRecorded {
            engagement_id: next_id,
            user,
            engagement_type,
            timestamp: current_timestamp,
            metadata,
        };

        env.events()
            .publish((symbol_short!("eng_rec"),), engagement_event);

        Ok(next_id)
    }

    /// Distribute reward for engagement
    pub fn distribute_reward(
        env: Env,
        admin: Address,
        engagement_id: u64,
        reward_amount: i128,
    ) -> Result<(), RewardError> {
        admin.require_auth();

        let init_key = symbol_short!("init");
        if !env.storage().persistent().has(&init_key) {
            return Err(RewardError::NotInitialized);
        }

        // Verify admin
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&symbol_short!("admin"))
            .ok_or(RewardError::Unauthorized)?;

        if admin != stored_admin {
            return Err(RewardError::Unauthorized);
        }

        if reward_amount <= 0 {
            return Err(RewardError::InvalidAmount);
        }

        // Get engagement
        let engagement_key = (symbol_short!("eng"), engagement_id);
        let engagement: Engagement = env
            .storage()
            .persistent()
            .get(&engagement_key)
            .ok_or(RewardError::EngagementNotFound)?;

        let current_timestamp = env.ledger().timestamp();

        // Emit RewardDistributed event
        let reward_event = RewardDistributed {
            engagement_id,
            user: engagement.user,
            reward_amount,
            timestamp: current_timestamp,
        };

        env.events()
            .publish((symbol_short!("rew_dist"),), reward_event);

        Ok(())
    }

    /// Adds a reward. Fails if amount is 0 (to simulate validation logic).
    pub fn add_reward(env: Env, user: Address, amount: i128) -> Result<(), RewardError> {
        if amount <= 0 {
            return Err(RewardError::InvalidAmount);
        }

        let init_key = symbol_short!("init");
        if !env.storage().persistent().has(&init_key) {
            return Err(RewardError::NotInitialized);
        }

        // Create reward symbol before moving env
        let reward_type = Symbol::new(&env, "reward");

        // Record engagement as generic reward activity
        let _engagement_id = Self::record_engagement(env, user, reward_type, amount)?;

        Ok(())
    }
}
