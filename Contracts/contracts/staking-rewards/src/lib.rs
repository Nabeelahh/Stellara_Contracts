#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Map, Symbol,
};

mod storage_keys {
    use soroban_sdk::{symbol_short, Symbol};

    pub const ADMIN: Symbol = symbol_short!("admin");
    pub const STAKE_TOKEN: Symbol = symbol_short!("s_token");
    pub const REWARD_TOKEN: Symbol = symbol_short!("r_token");
    pub const POOL_CONFIG: Symbol = symbol_short!("p_cfg");
    pub const USER_STAKE: Symbol = symbol_short!("u_stake");
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidAmount = 4,
    InvalidPool = 5,
    InsufficientBalance = 6,
    StillLocked = 7,
    NothingToClaim = 8,
    ArithmeticOverflow = 9,
    ProposalNotFound = 10,
    ProposalNotActive = 11,
    TimelockNotExpired = 12,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterProposal {
    pub id: u64,
    pub proposer: Address,
    pub parameter_key: Symbol,
    pub old_value: u128,
    pub new_value: u128,
    pub proposed_at: u64,
    pub executes_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

const TIMELOCK_DELAY: u64 = 86400; // 24 hours in seconds

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    pub lockup_seconds: u64,
    pub apy_bps: u32, // APY in basis points (100 = 1%)
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserStake {
    pub amount: i128,
    pub pool_id: u32,
    pub start_timestamp: u64,
    pub last_claim_timestamp: u64,
}

#[contract]
pub struct StakingRewardsContract;

#[contractimpl]
impl StakingRewardsContract {
    /// Initialize the contract with admin and token details
    pub fn initialize(
        env: Env,
        admin: Address,
        staking_token: Address,
        reward_token: Address,
    ) -> Result<(), ContractError> {
        if env.storage().instance().has(&storage_keys::ADMIN) {
            return Err(ContractError::AlreadyInitialized);
        }

        env.storage().instance().set(&storage_keys::ADMIN, &admin);
        env.storage()
            .instance()
            .set(&storage_keys::STAKE_TOKEN, &staking_token);
        env.storage()
            .instance()
            .set(&storage_keys::REWARD_TOKEN, &reward_token);

        // Define default pools: 30, 60, 90 days
        let pools = soroban_sdk::vec![
            &env,
            PoolConfig {
                lockup_seconds: 30 * 24 * 60 * 60,
                apy_bps: 500, // 5%
            },
            PoolConfig {
                lockup_seconds: 60 * 24 * 60 * 60,
                apy_bps: 1000, // 10%
            },
            PoolConfig {
                lockup_seconds: 90 * 24 * 60 * 60,
                apy_bps: 1500, // 15%
            },
        ];
        env.storage()
            .instance()
            .set(&storage_keys::POOL_CONFIG, &pools);

        Ok(())
    }

    /// Stake tokens in a specific pool
    pub fn stake(env: Env, user: Address, amount: i128, pool_id: u32) -> Result<(), ContractError> {
        user.require_auth();

        if amount <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        let pools: soroban_sdk::Vec<PoolConfig> = env
            .storage()
            .instance()
            .get(&storage_keys::POOL_CONFIG)
            .ok_or(ContractError::NotInitialized)?;

        if pool_id >= pools.len() {
            return Err(ContractError::InvalidPool);
        }

        let staking_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::STAKE_TOKEN)
            .unwrap();

        // Transfer tokens to contract
        let client = soroban_sdk::token::Client::new(&env, &staking_token);
        client.transfer(&user, &env.current_contract_address(), &amount);

        let key = (storage_keys::USER_STAKE, user.clone());
        let mut user_stake = env
            .storage()
            .persistent()
            .get::<_, UserStake>(&key)
            .unwrap_or(UserStake {
                amount: 0,
                pool_id,
                start_timestamp: env.ledger().timestamp(),
                last_claim_timestamp: env.ledger().timestamp(),
            });

        // For simplicity, if they already have a stake, they must unstake first or we just update
        // In this implementation, we allow adding to stake but reset the timer for the whole amount
        user_stake.amount = user_stake
            .amount
            .checked_add(amount)
            .ok_or(ContractError::ArithmeticOverflow)?;
        user_stake.pool_id = pool_id;
        user_stake.start_timestamp = env.ledger().timestamp();
        user_stake.last_claim_timestamp = env.ledger().timestamp();

        env.storage().persistent().set(&key, &user_stake);

        env.events().publish(
            (symbol_short!("stake"), user),
            (amount, pool_id, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Claim rewards for the user
    pub fn claim(env: Env, user: Address) -> Result<i128, ContractError> {
        user.require_auth();

        let key = (storage_keys::USER_STAKE, user.clone());
        let mut user_stake: UserStake = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::NothingToClaim)?;

        let reward_amount = calculate_rewards(&env, &user_stake)?;
        if reward_amount <= 0 {
            return Err(ContractError::NothingToClaim);
        }

        let reward_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::REWARD_TOKEN)
            .unwrap();

        let client = soroban_sdk::token::Client::new(&env, &reward_token);
        client.transfer(&env.current_contract_address(), &user, &reward_amount);

        user_stake.last_claim_timestamp = env.ledger().timestamp();
        env.storage().persistent().set(&key, &user_stake);

        env.events().publish(
            (symbol_short!("claim"), user),
            (reward_amount, env.ledger().timestamp()),
        );

        Ok(reward_amount)
    }

    /// Unstake principal and any pending rewards
    pub fn unstake(env: Env, user: Address) -> Result<i128, ContractError> {
        user.require_auth();

        let key = (storage_keys::USER_STAKE, user.clone());
        let user_stake: UserStake = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::NothingToClaim)?;

        let pools: soroban_sdk::Vec<PoolConfig> = env
            .storage()
            .instance()
            .get(&storage_keys::POOL_CONFIG)
            .unwrap();

        let pool = pools.get_unchecked(user_stake.pool_id);
        let now = env.ledger().timestamp();
        let elapsed = now.saturating_sub(user_stake.start_timestamp);

        let mut principal_to_return = user_stake.amount;

        // Apply early withdrawal penalty if lockup hasn't expired
        if elapsed < pool.lockup_seconds {
            let penalty_bps: i128 = 1000; // 10% penalty
            let penalty_amount = principal_to_return
                .checked_mul(penalty_bps)
                .and_then(|v| v.checked_div(10000))
                .ok_or(ContractError::ArithmeticOverflow)?;
            principal_to_return = principal_to_return
                .checked_sub(penalty_amount)
                .ok_or(ContractError::ArithmeticOverflow)?;

            // Penalty stays in the contract (could be sent to a treasury)
        }

        // Pay out any pending rewards before removing stake
        let reward_amount = calculate_rewards(&env, &user_stake).unwrap_or(0);
        if reward_amount > 0 {
            let reward_token: Address = env
                .storage()
                .instance()
                .get(&storage_keys::REWARD_TOKEN)
                .unwrap();
            soroban_sdk::token::Client::new(&env, &reward_token).transfer(
                &env.current_contract_address(),
                &user,
                &reward_amount,
            );
        }

        let staking_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::STAKE_TOKEN)
            .unwrap();

        soroban_sdk::token::Client::new(&env, &staking_token).transfer(
            &env.current_contract_address(),
            &user,
            &principal_to_return,
        );

        // Emit the claim event once using the already-transferred reward amount.
        if reward_amount > 0 {
            env.events().publish(
                (symbol_short!("claim"), user.clone()),
                (reward_amount, env.ledger().timestamp()),
            );
        }

        // Remove stake
        env.storage().persistent().remove(&key);

        env.events().publish(
            (symbol_short!("unstake"), user),
            (principal_to_return, reward_amount, env.ledger().timestamp()),
        );

        Ok(principal_to_return)
    }

    /// Re-stake pending rewards (Auto-compounding)
    pub fn compound(env: Env, user: Address) -> Result<(), ContractError> {
        user.require_auth();

        let key = (storage_keys::USER_STAKE, user.clone());
        let mut user_stake: UserStake = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::NothingToClaim)?;

        let reward_amount = calculate_rewards(&env, &user_stake)?;
        if reward_amount <= 0 {
            return Err(ContractError::NothingToClaim);
        }

        // Logic check: reward token must be the same as staking token for auto-compound
        let staking_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::STAKE_TOKEN)
            .unwrap();
        let reward_token: Address = env
            .storage()
            .instance()
            .get(&storage_keys::REWARD_TOKEN)
            .unwrap();

        if staking_token != reward_token {
            return Err(ContractError::Unauthorized); // Or a more specific error
        }

        user_stake.amount = user_stake
            .amount
            .checked_add(reward_amount)
            .ok_or(ContractError::ArithmeticOverflow)?;
        user_stake.last_claim_timestamp = env.ledger().timestamp();
        env.storage().persistent().set(&key, &user_stake);

        env.events().publish(
            (symbol_short!("compound"), user),
            (reward_amount, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Get user's current stake info
    pub fn get_stake(env: Env, user: Address) -> Option<UserStake> {
        let key = (storage_keys::USER_STAKE, user);
        env.storage().persistent().get(&key)
    }

    /// Get pending rewards for a user
    pub fn get_pending_rewards(env: Env, user: Address) -> i128 {
        let key = (storage_keys::USER_STAKE, user);
        if let Some(user_stake) = env.storage().persistent().get::<_, UserStake>(&key) {
            return calculate_rewards(&env, &user_stake).unwrap_or(0);
        }
        0
    }

    /// Propose a parameter change (governance-controlled)
    pub fn propose_parameter_change(
        env: Env,
        admin: Address,
        parameter_key: Symbol,
        new_value: u128,
    ) -> Result<u64, ContractError> {
        Self::require_admin(&env, &admin)?;

        let params_map_key = symbol_short!("gov_vals");
        let params_map: Map<Symbol, u128> = env
            .storage()
            .instance()
            .get(&params_map_key)
            .unwrap_or_else(|| Map::new(&env));

        let old_value = params_map.get(parameter_key.clone()).unwrap_or(0);

        let proposal_id = env
            .storage()
            .instance()
            .get::<Symbol, u64>(&symbol_short!("pcnt"))
            .unwrap_or(0)
            + 1;

        let proposal = ParameterProposal {
            id: proposal_id,
            proposer: admin,
            parameter_key: parameter_key.clone(),
            old_value,
            new_value,
            proposed_at: env.ledger().timestamp(),
            executes_at: env.ledger().timestamp() + TIMELOCK_DELAY,
            executed: false,
            cancelled: false,
        };

        let proposals_key = symbol_short!("pprop");
        let mut proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .unwrap_or_else(|| Map::new(&env));

        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&proposals_key, &proposals);
        env.storage()
            .instance()
            .set(&symbol_short!("pcnt"), &proposal_id);

        env.events().publish(
            (symbol_short!("pprop"), proposal_id),
            (parameter_key, new_value, env.ledger().timestamp()),
        );

        Ok(proposal_id)
    }

    /// Execute a parameter change after timelock (governance-controlled)
    pub fn execute_parameter_change(
        env: Env,
        admin: Address,
        proposal_id: u64,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &admin)?;

        let proposals_key = symbol_short!("pprop");
        let mut proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ContractError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(ContractError::ProposalNotFound)?;

        if proposal.executed || proposal.cancelled {
            return Err(ContractError::ProposalNotActive);
        }

        if env.ledger().timestamp() < proposal.executes_at {
            return Err(ContractError::TimelockNotExpired);
        }

        let params_map_key = symbol_short!("gov_vals");
        let mut params_map: Map<Symbol, u128> = env
            .storage()
            .instance()
            .get(&params_map_key)
            .unwrap_or_else(|| Map::new(&env));

        params_map.set(proposal.parameter_key.clone(), proposal.new_value);
        env.storage().instance().set(&params_map_key, &params_map);

        proposal.executed = true;
        proposals.set(proposal_id, proposal.clone());
        env.storage().instance().set(&proposals_key, &proposals);

        env.events().publish(
            (symbol_short!("pexec"), proposal_id),
            (proposal.parameter_key, proposal.new_value, env.ledger().timestamp()),
        );

        Ok(())
    }

    /// Cancel a parameter proposal (governance-controlled)
    pub fn cancel_parameter_proposal(
        env: Env,
        admin: Address,
        proposal_id: u64,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &admin)?;

        let proposals_key = symbol_short!("pprop");
        let mut proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ContractError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(ContractError::ProposalNotFound)?;

        if proposal.executed {
            return Err(ContractError::ProposalNotActive);
        }

        proposal.cancelled = true;
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&proposals_key, &proposals);

        env.events().publish(
            (symbol_short!("pcancel"), proposal_id),
            (env.ledger().timestamp(),),
        );

        Ok(())
    }

    /// Get parameter proposal details
    pub fn get_parameter_proposal(
        env: Env,
        proposal_id: u64,
    ) -> Result<ParameterProposal, ContractError> {
        let proposals_key = symbol_short!("pprop");
        let proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ContractError::ProposalNotFound)?;

        proposals
            .get(proposal_id)
            .ok_or(ContractError::ProposalNotFound)
    }

    /// Check if the caller is admin
    fn require_admin(env: &Env, admin: &Address) -> Result<(), ContractError> {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&storage_keys::ADMIN)
            .ok_or(ContractError::NotInitialized)?;

        if admin != &stored_admin {
            return Err(ContractError::Unauthorized);
        }

        Ok(())
    }
}

fn calculate_rewards(env: &Env, user_stake: &UserStake) -> Result<i128, ContractError> {
    let pools: soroban_sdk::Vec<PoolConfig> = env
        .storage()
        .instance()
        .get(&storage_keys::POOL_CONFIG)
        .ok_or(ContractError::NotInitialized)?;

    if user_stake.pool_id >= pools.len() {
        return Err(ContractError::InvalidPool);
    }

    let pool = pools.get(user_stake.pool_id).unwrap();
    let now = env.ledger().timestamp();
    let elapsed_seconds = now.saturating_sub(user_stake.last_claim_timestamp);

    if elapsed_seconds == 0 {
        return Ok(0);
    }

    // Reward = Principal * APY * (elapsed / seconds_in_year)
    // APY is in basis points (e.g. 500 = 5%)
    let seconds_in_year: u64 = 365 * 24 * 60 * 60;

    // Checked arithmetic prevents silent overflow on large stakes, high APY, or long durations
    let amount_times_apy = user_stake
        .amount
        .checked_mul(pool.apy_bps as i128)
        .ok_or(ContractError::ArithmeticOverflow)?;
    let numerator = amount_times_apy
        .checked_mul(elapsed_seconds as i128)
        .ok_or(ContractError::ArithmeticOverflow)?;
    let denominator = 10000_i128
        .checked_mul(seconds_in_year as i128)
        .ok_or(ContractError::ArithmeticOverflow)?;
    let reward = numerator
        .checked_div(denominator)
        .ok_or(ContractError::ArithmeticOverflow)?;

    Ok(reward)
}

#[cfg(test)]
mod test;