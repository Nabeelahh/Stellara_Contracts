#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec,
};

mod storage_keys {
    use soroban_sdk::{symbol_short, Symbol};

    pub const ADMIN: Symbol = symbol_short!("admin");
    pub const LP_TOKEN: Symbol = symbol_short!("lp_token");
    pub const REWARD_TOKEN: Symbol = symbol_short!("r_token");
    pub const GOVERNANCE_TOKEN: Symbol = symbol_short!("gov_token");
    pub const POOL_CONFIG: Symbol = symbol_short!("pool_cfg");
    pub const EMISSION_SCHEDULE: Symbol = symbol_short!("emit_sch");
    pub const USER_LP_STAKE: Symbol = symbol_short!("u_lp"); // User LP balances
    pub const USER_LOCKED_REWARDS: Symbol = symbol_short!("u_locked"); // User locked rewards for governance
    pub const TOTAL_LP_STAKED: Symbol = symbol_short!("total_lp");
    pub const LAST_REWARD_BLOCK: Symbol = symbol_short!("last_reward");
    pub const MULTIPLIER_CONFIG: Symbol = symbol_short!("mult_cfg");
    pub const PAIR_LIST: Symbol = symbol_short!("pair_list");
    pub const INITIALIZED: Symbol = symbol_short!("init");
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum LiquidityMiningError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidAmount = 4,
    InvalidPair = 5,
    InsufficientBalance = 6,
    InsufficientRewardBalance = 7,
    NoRewardsToClaim = 8,
    InvalidEmissionSchedule = 9,
    InvalidMultiplier = 10,
    PairAlreadyExists = 11,
    InvalidLockupPeriod = 12,
    StillLocked = 13,
}

/// Pair configuration for liquidity mining
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairConfig {
    pub pair_id: u32,
    pub pair_symbol: Symbol,      // e.g., "USDC_STELLAR"
    pub emissions_per_block: i128, // Reward tokens per block
    pub total_allocated: i128,    // Total rewards allocated to this pair
    pub accumulated_reward_per_share: i128, // Used for tracking cumulative rewards
    pub last_update_block: u64,
    pub active: bool,
}

/// User's liquidity provision stake
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LPStake {
    pub user: Address,
    pub pair_id: u32,
    pub lp_balance: i128,            // Amount of LP tokens staked
    pub start_timestamp: u64,        // When they started providing liquidity
    pub reward_debt: i128,           // Tracks claimed rewards to prevent double-counting
    pub bonus_multiplier_tier: u32,  // 0=none, 1=2x, 2=3x, 3=5x based on lockup
}

/// Emission schedule configuration
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmissionSchedule {
    pub start_block: u64,
    pub end_block: u64,
    pub total_emissions: i128,
    pub emissions_per_block: i128,
    pub halving_block_interval: u64, // Halving every N blocks (optional)
    pub active: bool,
}

/// Bonus multiplier configuration for long-term staking
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiplierConfig {
    pub lockup_tier_1_days: u64,   // 30 days = 2x multiplier
    pub multiplier_tier_1: u32,    // 200 (2x)
    pub lockup_tier_2_days: u64,   // 90 days = 3x multiplier
    pub multiplier_tier_2: u32,    // 300 (3x)
    pub lockup_tier_3_days: u64,   // 180 days = 5x multiplier
    pub multiplier_tier_3: u32,    // 500 (5x)
}

/// Event: Liquidity provided
#[contracttype]
#[derive(Clone, Debug)]
pub struct LiquidityProvided {
    pub user: Address,
    pub pair_id: u32,
    pub lp_amount: i128,
    pub timestamp: u64,
}

/// Event: Liquidity withdrawn
#[contracttype]
#[derive(Clone, Debug)]
pub struct LiquidityWithdrawn {
    pub user: Address,
    pub pair_id: u32,
    pub lp_amount: i128,
    pub timestamp: u64,
}

/// Event: Rewards claimed
#[contracttype]
#[derive(Clone, Debug)]
pub struct RewardsClaimed {
    pub user: Address,
    pub pair_id: u32,
    pub reward_amount: i128,
    pub governance_locked: i128,
    pub timestamp: u64,
}

/// Event: Rewards locked for governance
#[contracttype]
#[derive(Clone, Debug)]
pub struct GovernanceLocked {
    pub user: Address,
    pub governance_power: i128,
    pub lockup_duration: u64,
    pub timestamp: u64,
}

#[contract]
pub struct LiquidityMiningContract;

#[contractimpl]
impl LiquidityMiningContract {
    /// Initialize the liquidity mining contract
    pub fn initialize(
        env: Env,
        admin: Address,
        lp_token: Address,
        reward_token: Address,
        governance_token: Address,
    ) -> Result<(), LiquidityMiningError> {
        if env.storage().instance().has(&storage_keys::INITIALIZED) {
            return Err(LiquidityMiningError::AlreadyInitialized);
        }

        env.storage().instance().set(&storage_keys::ADMIN, &admin);
        env.storage()
            .instance()
            .set(&storage_keys::LP_TOKEN, &lp_token);
        env.storage()
            .instance()
            .set(&storage_keys::REWARD_TOKEN, &reward_token);
        env.storage()
            .instance()
            .set(&storage_keys::GOVERNANCE_TOKEN, &governance_token);

        // Initialize empty pair list
        let empty_list: Vec<u32> = Vec::new(&env);
        env.storage()
            .instance()
            .set(&storage_keys::PAIR_LIST, &empty_list);

        // Default multiplier configuration
        let multiplier_config = MultiplierConfig {
            lockup_tier_1_days: 30,
            multiplier_tier_1: 200,    // 2x
            lockup_tier_2_days: 90,
            multiplier_tier_2: 300,    // 3x
            lockup_tier_3_days: 180,
            multiplier_tier_3: 500,    // 5x
        };
        env.storage()
            .instance()
            .set(&storage_keys::MULTIPLIER_CONFIG, &multiplier_config);

        env.storage()
            .instance()
            .set(&storage_keys::TOTAL_LP_STAKED, &0i128);
        env.storage()
            .instance()
            .set(&storage_keys::LAST_REWARD_BLOCK, &env.ledger().sequence());

        env.storage()
            .instance()
            .set(&storage_keys::INITIALIZED, &true);

        Ok(())
    }

    /// Create a new liquidity mining pair (admin only)
    pub fn create_pair(
        env: Env,
        admin: Address,
        pair_id: u32,
        pair_symbol: Symbol,
        emissions_per_block: i128,
        total_allocated: i128,
    ) -> Result<(), LiquidityMiningError> {
        admin.require_auth();
        Self::require_initialized(&env)?;

        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&storage_keys::ADMIN)
            .ok_or(LiquidityMiningError::NotInitialized)?;

        if admin != stored_admin {
            return Err(LiquidityMiningError::Unauthorized);
        }

        if emissions_per_block <= 0 || total_allocated <= 0 {
            return Err(LiquidityMiningError::InvalidAmount);
        }

        let current_block = env.ledger().sequence();

        let pair_config = PairConfig {
            pair_id,
            pair_symbol,
            emissions_per_block,
            total_allocated,
            accumulated_reward_per_share: 0,
            last_update_block: current_block,
            active: true,
        };

        let pair_key = (symbol_short!("pair"), pair_id);
        let existing = env.storage().persistent().get::<_, PairConfig>(&pair_key);
        if existing.is_some() {
            return Err(LiquidityMiningError::PairAlreadyExists);
        }

        env.storage().persistent().set(&pair_key, &pair_config);

        // Add to pair list
        let mut pair_list: Vec<u32> = env
            .storage()
            .instance()
            .get(&storage_keys::PAIR_LIST)
            .unwrap_or(Vec::new(&env));
        pair_list.push_back(pair_id);
        env.storage()
            .instance()
            .set(&storage_keys::PAIR_LIST, &pair_list);

        env.events().publish(
            (symbol_short!("pair_new"),),
            (pair_id, pair_symbol, emissions_per_block),
        );

        Ok(())
    }

    /// Provide liquidity to a pair
    pub fn provide_liquidity(
        env: Env,
        user: Address,
        pair_id: u32,
        lp_amount: i128,
    ) -> Result<(), LiquidityMiningError> {
        user.require_auth();
        Self::require_initialized(&env)?;

        if lp_amount <= 0 {
            return Err(LiquidityMiningError::InvalidAmount);
        }

        // Get pair configuration
        let pair_key = (symbol_short!("pair"), pair_id);
        let pair_config: PairConfig = env
            .storage()
            .persistent()
            .get(&pair_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        if !pair_config.active {
            return Err(LiquidityMiningError::InvalidPair);
        }

        // Update accumulated rewards
        Self::update_pair_rewards(&env, pair_id)?;

        // Get or create user LP stake
        let stake_key = (symbol_short!("lp_stake"), user.clone(), pair_id);
        let mut user_stake: LPStake = env
            .storage()
            .persistent()
            .get(&stake_key)
            .unwrap_or(LPStake {
                user: user.clone(),
                pair_id,
                lp_balance: 0,
                start_timestamp: env.ledger().timestamp(),
                reward_debt: 0,
                bonus_multiplier_tier: 0,
            });

        // Transfer LP tokens to contract
        let lp_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::LP_TOKEN)
            .ok_or(LiquidityMiningError::NotInitialized)?;

        let token_client = soroban_sdk::token::Client::new(&env, &lp_token);
        token_client.transfer(&user, &env.current_contract_address(), &lp_amount);

        user_stake.lp_balance += lp_amount;
        env.storage().persistent().set(&stake_key, &user_stake);

        // Update total LP staked
        let total: i128 = env
            .storage()
            .instance()
            .get(&storage_keys::TOTAL_LP_STAKED)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&storage_keys::TOTAL_LP_STAKED, &(total + lp_amount));

        env.events().publish(
            (symbol_short!("liq_prov"),),
            LiquidityProvided {
                user: user.clone(),
                pair_id,
                lp_amount,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Withdraw liquidity from a pair
    pub fn withdraw_liquidity(
        env: Env,
        user: Address,
        pair_id: u32,
        lp_amount: i128,
    ) -> Result<(), LiquidityMiningError> {
        user.require_auth();
        Self::require_initialized(&env)?;

        if lp_amount <= 0 {
            return Err(LiquidityMiningError::InvalidAmount);
        }

        let stake_key = (symbol_short!("lp_stake"), user.clone(), pair_id);
        let mut user_stake: LPStake = env
            .storage()
            .persistent()
            .get(&stake_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        if user_stake.lp_balance < lp_amount {
            return Err(LiquidityMiningError::InsufficientBalance);
        }

        // Check lockup period if multiplier was applied
        if user_stake.bonus_multiplier_tier > 0 {
            let multiplier_config: MultiplierConfig = env
                .storage()
                .instance()
                .get(&storage_keys::MULTIPLIER_CONFIG)
                .ok_or(LiquidityMiningError::InvalidMultiplier)?;

            let required_seconds = match user_stake.bonus_multiplier_tier {
                1 => multiplier_config.lockup_tier_1_days * 24 * 60 * 60,
                2 => multiplier_config.lockup_tier_2_days * 24 * 60 * 60,
                3 => multiplier_config.lockup_tier_3_days * 24 * 60 * 60,
                _ => 0,
            };

            let elapsed = env.ledger().timestamp() - user_stake.start_timestamp;
            if elapsed < required_seconds {
                return Err(LiquidityMiningError::StillLocked);
            }
        }

        // Update accumulated rewards
        Self::update_pair_rewards(&env, pair_id)?;

        // Calculate and transfer pending rewards before withdrawal
        let pending_reward = Self::calculate_pending_reward(&env, user.clone(), pair_id)?;
        if pending_reward > 0 {
            Self::claim_rewards_internal(&env, user.clone(), pair_id, pending_reward)?;
        }

        user_stake.lp_balance -= lp_amount;
        env.storage().persistent().set(&stake_key, &user_stake);

        // Update total LP staked
        let total: i128 = env
            .storage()
            .instance()
            .get(&storage_keys::TOTAL_LP_STAKED)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&storage_keys::TOTAL_LP_STAKED, &(total - lp_amount));

        // Transfer LP tokens back to user
        let lp_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::LP_TOKEN)
            .ok_or(LiquidityMiningError::NotInitialized)?;

        let token_client = soroban_sdk::token::Client::new(&env, &lp_token);
        token_client.transfer(&env.current_contract_address(), &user, &lp_amount);

        env.events().publish(
            (symbol_short!("liq_with"),),
            LiquidityWithdrawn {
                user: user.clone(),
                pair_id,
                lp_amount,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Lock rewards for governance power (50% locked = governance token allocation)
    pub fn lock_rewards_for_governance(
        env: Env,
        user: Address,
        pair_id: u32,
        lockup_days: u64,
    ) -> Result<(), LiquidityMiningError> {
        user.require_auth();
        Self::require_initialized(&env)?;

        if lockup_days == 0 || lockup_days > 365 {
            return Err(LiquidityMiningError::InvalidLockupPeriod);
        }

        // Calculate pending rewards
        let pending_reward = Self::calculate_pending_reward(&env, user.clone(), pair_id)?;

        if pending_reward <= 0 {
            return Err(LiquidityMiningError::NoRewardsToClaim);
        }

        // 50% of the reward is locked for governance
        let governance_amount = pending_reward / 2;

        // Store locked governance power
        let locked_key = (symbol_short!("locked"), user.clone());
        let mut locked_rewards: i128 = env
            .storage()
            .persistent()
            .get(&locked_key)
            .unwrap_or(0);
        locked_rewards += governance_amount;
        env.storage().persistent().set(&locked_key, &locked_rewards);

        // Claim the remaining 50% normally
        Self::claim_rewards_internal(&env, user.clone(), pair_id, pending_reward)?;

        env.events().publish(
            (symbol_short!("gov_lock"),),
            GovernanceLocked {
                user: user.clone(),
                governance_power: governance_amount,
                lockup_duration: lockup_days,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Claim rewards for a pair
    pub fn claim_rewards(
        env: Env,
        user: Address,
        pair_id: u32,
    ) -> Result<i128, LiquidityMiningError> {
        user.require_auth();
        Self::require_initialized(&env)?;

        // Calculate pending rewards
        let pending_reward = Self::calculate_pending_reward(&env, user.clone(), pair_id)?;

        if pending_reward <= 0 {
            return Err(LiquidityMiningError::NoRewardsToClaim);
        }

        Self::claim_rewards_internal(&env, user.clone(), pair_id, pending_reward)
    }

    /// Get user's LP balance for a pair
    pub fn get_lp_balance(env: Env, user: Address, pair_id: u32) -> Result<i128, LiquidityMiningError> {
        Self::require_initialized(&env)?;

        let stake_key = (symbol_short!("lp_stake"), user, pair_id);
        let user_stake: LPStake = env
            .storage()
            .persistent()
            .get(&stake_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        Ok(user_stake.lp_balance)
    }

    /// Calculate pending rewards (does not include bonus multiplier for now, handled in claim)
    pub fn get_pending_rewards(
        env: Env,
        user: Address,
        pair_id: u32,
    ) -> Result<i128, LiquidityMiningError> {
        Self::require_initialized(&env)?;
        Self::calculate_pending_reward(&env, user, pair_id)
    }

    /// Get governance power (locked rewards)
    pub fn get_governance_power(env: Env, user: Address) -> Result<i128, LiquidityMiningError> {
        Self::require_initialized(&env)?;

        let locked_key = (symbol_short!("locked"), user);
        let governance_power: i128 = env
            .storage()
            .persistent()
            .get(&locked_key)
            .unwrap_or(0);

        Ok(governance_power)
    }

    /// Get APR/APY for a pair (simplified calculation)
    pub fn get_apy(env: Env, pair_id: u32) -> Result<u32, LiquidityMiningError> {
        Self::require_initialized(&env)?;

        let pair_key = (symbol_short!("pair"), pair_id);
        let pair_config: PairConfig = env
            .storage()
            .persistent()
            .get(&pair_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        let total_staked: i128 = env
            .storage()
            .instance()
            .get(&storage_keys::TOTAL_LP_STAKED)
            .unwrap_or(1); // Avoid division by zero

        if total_staked == 0 {
            return Ok(0);
        }

        // Simplified APY = (annual emissions / total staked) * 100 * 100 (basis points)
        // Assuming ~6500 blocks per day
        let blocks_per_year = 6500 * 365;
        let annual_emissions = pair_config.emissions_per_block * blocks_per_year;
        let apy_basis_points = (annual_emissions * 10000) / total_staked;

        Ok(apy_basis_points as u32)
    }

    /// Get list of all active pairs
    pub fn get_pairs(env: Env) -> Result<Vec<u32>, LiquidityMiningError> {
        Self::require_initialized(&env)?;

        let pair_list: Vec<u32> = env
            .storage()
            .instance()
            .get(&storage_keys::PAIR_LIST)
            .unwrap_or(Vec::new(&env));

        Ok(pair_list)
    }

    // ============= INTERNAL FUNCTIONS =============

    fn require_initialized(env: &Env) -> Result<(), LiquidityMiningError> {
        if !env.storage().instance().has(&storage_keys::INITIALIZED) {
            return Err(LiquidityMiningError::NotInitialized);
        }
        Ok(())
    }

    fn claim_rewards_internal(
        env: &Env,
        user: Address,
        pair_id: u32,
        pending_reward: i128,
    ) -> Result<i128, LiquidityMiningError> {
        if pending_reward <= 0 {
            return Ok(0);
        }

        let reward_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::REWARD_TOKEN)
            .ok_or(LiquidityMiningError::NotInitialized)?;

        let token_client = soroban_sdk::token::Client::new(env, &reward_token);

        // Check if contract has enough reward balance
        let contract_balance = token_client.balance(&env.current_contract_address());
        if contract_balance < pending_reward {
            return Err(LiquidityMiningError::InsufficientRewardBalance);
        }

        // Transfer reward tokens to user
        token_client.transfer(&env.current_contract_address(), &user, &pending_reward);

        // Update reward debt
        let stake_key = (symbol_short!("lp_stake"), user.clone(), pair_id);
        let mut user_stake: LPStake = env
            .storage()
            .persistent()
            .get(&stake_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        user_stake.reward_debt += pending_reward;
        env.storage().persistent().set(&stake_key, &user_stake);

        env.events().publish(
            (symbol_short!("reward_cl"),),
            RewardsClaimed {
                user,
                pair_id,
                reward_amount: pending_reward,
                governance_locked: 0,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(pending_reward)
    }

    fn calculate_pending_reward(
        env: &Env,
        user: Address,
        pair_id: u32,
    ) -> Result<i128, LiquidityMiningError> {
        let stake_key = (symbol_short!("lp_stake"), user.clone(), pair_id);
        let user_stake: LPStake = env
            .storage()
            .persistent()
            .get(&stake_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        let pair_key = (symbol_short!("pair"), pair_id);
        let pair_config: PairConfig = env
            .storage()
            .persistent()
            .get(&pair_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        let total_staked: i128 = env
            .storage()
            .instance()
            .get(&storage_keys::TOTAL_LP_STAKED)
            .unwrap_or(1);

        if total_staked == 0 || user_stake.lp_balance == 0 {
            return Ok(0);
        }

        let blocks_since_last_claim = env.ledger().sequence() - pair_config.last_update_block;
        let reward_per_block = pair_config.emissions_per_block;
        let user_reward_share = (user_stake.lp_balance * reward_per_block * blocks_since_last_claim) / total_staked;

        // Apply bonus multiplier if applicable
        let multiplier = Self::get_bonus_multiplier(&env, user_stake.bonus_multiplier_tier)?;
        let final_reward = (user_reward_share * multiplier) / 100;

        Ok(final_reward - user_stake.reward_debt)
    }

    fn update_pair_rewards(env: &Env, pair_id: u32) -> Result<(), LiquidityMiningError> {
        let pair_key = (symbol_short!("pair"), pair_id);
        let mut pair_config: PairConfig = env
            .storage()
            .persistent()
            .get(&pair_key)
            .ok_or(LiquidityMiningError::InvalidPair)?;

        pair_config.last_update_block = env.ledger().sequence();
        env.storage().persistent().set(&pair_key, &pair_config);

        Ok(())
    }

    fn get_bonus_multiplier(env: &Env, tier: u32) -> Result<u32, LiquidityMiningError> {
        match tier {
            0 => Ok(100),  // 1x
            1 => Ok(200),  // 2x
            2 => Ok(300),  // 3x
            3 => Ok(500),  // 5x
            _ => Err(LiquidityMiningError::InvalidMultiplier),
        }
    }
}

#[cfg(test)]
mod test;
