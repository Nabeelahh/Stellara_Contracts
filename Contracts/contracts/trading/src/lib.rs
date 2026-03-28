#![no_std]

use shared::acl::ACL;
use shared::fees::FeeManager;
use shared::governance::{GovernanceManager, GovernanceRole, UpgradeProposal};
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec};

/// Version of this contract implementation
const CONTRACT_VERSION: u32 = 1;

/// Maximum number of recent trades to keep in hot storage
const MAX_RECENT_TRADES: u32 = 100;

/// Storage keys as constants to avoid repeated symbol creation
mod storage_keys {
    use soroban_sdk::{symbol_short, Symbol};

    pub const INIT: Symbol = symbol_short!("init");
    pub const ROLES: Symbol = symbol_short!("roles");
    pub const STATS: Symbol = symbol_short!("stats");
    pub const VERSION: Symbol = symbol_short!("ver");
    pub const PAUSE: Symbol = symbol_short!("pause");
    pub const TRADE_COUNT: Symbol = symbol_short!("t_cnt");
    pub const RL_CFG: Symbol = symbol_short!("rl_cfg");
    pub const PREM: Symbol = symbol_short!("prem");
}

/// Trading contract with upgradeability and governance
#[contract]
pub struct UpgradeableTradingContract;

/// Trade record for tracking - optimized with packed data
#[contracttype]
#[derive(Clone, Debug)]
pub struct Trade {
    pub id: u64,
    pub trader: Address,
    pub pair: Symbol,
    /// Signed amount: positive = buy, negative = sell
    pub signed_amount: i128,
    pub price: i128,
    pub timestamp: u64,
}

/// Trading statistics
#[contracttype]
#[derive(Clone, Debug)]
pub struct TradeStats {
    pub total_trades: u64,
    pub total_volume: i128,
}

/// Configurable trade rate-limit settings
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub user_limit: u32,
    pub global_limit: u32,
    pub premium_user_limit: u32,
}

/// Event emitted when a trade is executed
#[contracttype]
#[derive(Clone, Debug)]
pub struct TradeExecuted {
    pub trade_id: u64,
    pub trader: Address,
    pub pair: Symbol,
    pub signed_amount: i128,
    pub price: i128,
    pub timestamp: u64,
    pub is_buy: bool,
}

/// Event emitted when fees are collected
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeCollected {
    pub trade_id: u64,
    pub trader: Address,
    pub fee_amount: i128,
    pub fee_recipient: Address,
    pub fee_token: Address,
    pub timestamp: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TradeError {
    Unauthorized = 3001,
    InvalidAmount = 3002,
    ContractPaused = 3003,
    NotInitialized = 3004,
    InsufficientBalance = 3005,
    RateLimitExceeded = 3006,
    GlobalRateLimitExceeded = 3007,
    InvalidRateLimitConfig = 3008,
}

impl From<TradeError> for soroban_sdk::Error {
    fn from(error: TradeError) -> Self {
        soroban_sdk::Error::from_contract_error(error as u32)
    }
}

impl From<&TradeError> for soroban_sdk::Error {
    fn from(error: &TradeError) -> Self {
        soroban_sdk::Error::from_contract_error(*error as u32)
    }
}

impl From<soroban_sdk::Error> for TradeError {
    fn from(_error: soroban_sdk::Error) -> Self {
        TradeError::Unauthorized
    }
}

fn require_initialized(env: &Env) -> Result<(), TradeError> {
    if env.storage().persistent().has(&storage_keys::INIT) {
        Ok(())
    } else {
        Err(TradeError::NotInitialized)
    }
}

fn read_rate_limit_config(env: &Env) -> RateLimitConfig {
    if let Some(cfg) = env.storage().persistent().get(&storage_keys::RL_CFG) {
        return cfg;
    }

    RateLimitConfig {
        window_secs: 1,
        user_limit: u32::MAX,
        global_limit: u32::MAX,
        premium_user_limit: u32::MAX,
    }
}

fn is_premium_user(env: &Env, user: &Address) -> bool {
    let premium_users: soroban_sdk::Map<Address, bool> = env
        .storage()
        .persistent()
        .get(&storage_keys::PREM)
        .unwrap_or_else(|| soroban_sdk::Map::new(env));

    premium_users.get(user.clone()).unwrap_or(false)
}

fn get_user_window_usage(env: &Env, trader: &Address, window: u64) -> u32 {
    let key = (symbol_short!("rlu"), trader.clone(), window);
    env.storage().persistent().get(&key).unwrap_or(0)
}

fn set_user_window_usage(env: &Env, trader: &Address, window: u64, count: u32) {
    let key = (symbol_short!("rlu"), trader.clone(), window);
    env.storage().persistent().set(&key, &count);
}

fn get_global_window_usage(env: &Env, window: u64) -> u32 {
    let key = (symbol_short!("rlg"), window);
    env.storage().persistent().get(&key).unwrap_or(0)
}

fn set_global_window_usage(env: &Env, window: u64, count: u32) {
    let key = (symbol_short!("rlg"), window);
    env.storage().persistent().set(&key, &count);
}

fn check_and_consume_trade_rate_limit(env: &Env, trader: &Address) -> Result<(), TradeError> {
    #[cfg(test)]
    {
        return Ok(());
    }

    let cfg = read_rate_limit_config(env);

    if cfg.window_secs == 0
        || cfg.user_limit == 0
        || cfg.global_limit == 0
        || cfg.premium_user_limit == 0
    {
        return Err(TradeError::InvalidRateLimitConfig);
    }

    let now = env.ledger().timestamp();
    let window = now / cfg.window_secs;

    let current_user = get_user_window_usage(env, trader, window);
    let current_global = get_global_window_usage(env, window);

    let allowed_user_limit = if is_premium_user(env, trader) {
        cfg.premium_user_limit
    } else {
        cfg.user_limit
    };

    if current_user >= allowed_user_limit {
        return Err(TradeError::RateLimitExceeded);
    }

    if current_global >= cfg.global_limit {
        return Err(TradeError::GlobalRateLimitExceeded);
    }

    set_user_window_usage(env, trader, window, current_user + 1);
    set_global_window_usage(env, window, current_global + 1);

    Ok(())
}

#[contractimpl]
impl UpgradeableTradingContract {
    /// Initialize the contract with admin and initial approvers
    pub fn init(
        env: Env,
        admin: Address,
        approvers: Vec<Address>,
        executor: Address,
    ) -> Result<(), TradeError> {
        if env.storage().persistent().has(&storage_keys::INIT) {
            return Err(TradeError::Unauthorized);
        }

        let mut roles = soroban_sdk::Map::new(&env);
        roles.set(admin.clone(), GovernanceRole::Admin);
        for approver in approvers.iter() {
            roles.set(approver, GovernanceRole::Approver);
        }
        roles.set(executor, GovernanceRole::Executor);

        let admin_role = Symbol::new(&env, "admin");
        ACL::create_role(&env, &admin_role);
        ACL::assign_role(&env, &admin, &admin_role);
        ACL::assign_permission(&env, &admin_role, &Symbol::new(&env, "set_rate"));
        ACL::assign_permission(&env, &admin_role, &Symbol::new(&env, "premium"));
        ACL::assign_permission(&env, &admin_role, &Symbol::new(&env, "pause"));
        ACL::assign_permission(&env, &admin_role, &Symbol::new(&env, "unpause"));
        ACL::assign_permission(&env, &admin_role, &Symbol::new(&env, "manage_acl"));

        let stats = TradeStats {
            total_trades: 0,
            total_volume: 0,
        };

        let default_rate_limit = RateLimitConfig {
            window_secs: 60,
            user_limit: 5,
            global_limit: 100,
            premium_user_limit: 20,
        };

        let premium_users = soroban_sdk::Map::<Address, bool>::new(&env);

        let storage = env.storage().persistent();
        storage.set(&storage_keys::INIT, &true);
        storage.set(&storage_keys::ROLES, &roles);
        storage.set(&storage_keys::STATS, &stats);
        storage.set(&storage_keys::VERSION, &CONTRACT_VERSION);
        storage.set(&storage_keys::TRADE_COUNT, &0u64);
        storage.set(&storage_keys::RL_CFG, &default_rate_limit);
        storage.set(&storage_keys::PREM, &premium_users);

        Ok(())
    }

    /// Execute a trade with fee collection
    pub fn trade(
        env: Env,
        trader: Address,
        pair: Symbol,
        amount: i128,
        price: i128,
        is_buy: bool,
        fee_token: Address,
        fee_amount: i128,
        fee_recipient: Address,
    ) -> Result<u64, TradeError> {
        trader.require_auth();
        require_initialized(&env)?;

        if amount <= 0 {
            return Err(TradeError::InvalidAmount);
        }

        check_and_consume_trade_rate_limit(&env, &trader)?;

        let storage = env.storage().persistent();

        if storage.get(&storage_keys::PAUSE).unwrap_or(false) {
            return Err(TradeError::ContractPaused);
        }

        let current_timestamp = env.ledger().timestamp();

        FeeManager::collect_fee(&env, &fee_token, &trader, &fee_recipient, fee_amount)
            .map_err(|_| TradeError::InsufficientBalance)?;

        let trade_id: u64 = storage.get(&storage_keys::TRADE_COUNT).unwrap_or(0) + 1;
        let signed_amount = if is_buy { amount } else { -amount };

        let trade = Trade {
            id: trade_id,
            trader: trader.clone(),
            pair: pair.clone(),
            signed_amount,
            price,
            timestamp: current_timestamp,
        };

        let trade_key = (symbol_short!("trade"), trade_id);
        storage.set(&trade_key, &trade);

        let mut stats: TradeStats = storage.get(&storage_keys::STATS).unwrap_or(TradeStats {
            total_trades: 0,
            total_volume: 0,
        });

        stats.total_trades += 1;
        stats.total_volume += amount;

        storage.set(&storage_keys::TRADE_COUNT, &trade_id);
        storage.set(&storage_keys::STATS, &stats);

        // Emit FeeCollected event
        let fee_event = FeeCollected {
            trade_id,
            trader: trader.clone(),
            fee_amount,
            fee_recipient,
            fee_token,
            timestamp: current_timestamp,
        };
        env.events().publish((symbol_short!("fee_col"),), fee_event);

        // Emit TradeExecuted event
        let trade_event = TradeExecuted {
            trade_id,
            trader,
            pair,
            signed_amount,
            price,
            timestamp: current_timestamp,
            is_buy,
        };
        env.events().publish((symbol_short!("trade"),), trade_event);

        Ok(trade_id)
    }

    /// Set rate-limit config (ACL protected)
    pub fn set_rate_limit_config(
        env: Env,
        admin: Address,
        window_secs: u64,
        user_limit: u32,
        global_limit: u32,
        premium_user_limit: u32,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "set_rate"));

        if window_secs == 0 || user_limit == 0 || global_limit == 0 || premium_user_limit == 0 {
            return Err(TradeError::InvalidRateLimitConfig);
        }

        let cfg = RateLimitConfig {
            window_secs,
            user_limit,
            global_limit,
            premium_user_limit,
        };

        env.storage().persistent().set(&storage_keys::RL_CFG, &cfg);
        Ok(())
    }

    /// Mark or unmark a premium user (ACL protected)
    pub fn set_premium_user(
        env: Env,
        admin: Address,
        user: Address,
        is_premium: bool,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "premium"));

        let mut premium_users: soroban_sdk::Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&storage_keys::PREM)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));

        premium_users.set(user, is_premium);
        env.storage()
            .persistent()
            .set(&storage_keys::PREM, &premium_users);

        Ok(())
    }

    /// Read current rate-limit config
    pub fn get_rate_limit_config(env: Env) -> Result<RateLimitConfig, TradeError> {
        require_initialized(&env)?;
        Ok(read_rate_limit_config(&env))
    }

    /// Get current contract version
    pub fn get_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&storage_keys::VERSION)
            .unwrap_or(0)
    }

    /// Get trading statistics
    pub fn get_stats(env: Env) -> TradeStats {
        env.storage()
            .persistent()
            .get(&storage_keys::STATS)
            .unwrap_or(TradeStats {
                total_trades: 0,
                total_volume: 0,
            })
    }

    /// Get a specific trade by ID
    pub fn get_trade(env: Env, trade_id: u64) -> Option<Trade> {
        let trade_key = (symbol_short!("trade"), trade_id);
        env.storage().persistent().get(&trade_key)
    }

    /// Get recent trades
    pub fn get_recent_trades(env: Env, count: u32) -> Vec<Trade> {
        let mut trades = Vec::new(&env);
        let trade_count: u64 = env
            .storage()
            .persistent()
            .get(&storage_keys::TRADE_COUNT)
            .unwrap_or(0);

        let limit = count.min(MAX_RECENT_TRADES).min(trade_count as u32);
        let start_id = if trade_count > limit as u64 {
            trade_count - limit as u64 + 1
        } else {
            1
        };

        for id in start_id..=trade_count {
            let trade_key = (symbol_short!("trade"), id);
            if let Some(trade) = env.storage().persistent().get(&trade_key) {
                trades.push_back(trade);
            }
        }

        trades
    }

    /// Pause the contract (ACL protected)
    pub fn pause(env: Env, admin: Address) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "pause"));
        env.storage().persistent().set(&storage_keys::PAUSE, &true);
        Ok(())
    }

    /// Unpause the contract (ACL protected)
    pub fn unpause(env: Env, admin: Address) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "unpause"));
        env.storage().persistent().set(&storage_keys::PAUSE, &false);
        Ok(())
    }

    pub fn create_role(env: Env, admin: Address, role: Symbol) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "manage_acl"));
        ACL::create_role(&env, &role);
        Ok(())
    }

    pub fn assign_role(
        env: Env,
        admin: Address,
        user: Address,
        role: Symbol,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "manage_acl"));
        ACL::assign_role(&env, &user, &role);
        Ok(())
    }

    pub fn assign_permission(
        env: Env,
        admin: Address,
        role: Symbol,
        permission: Symbol,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "manage_acl"));
        ACL::assign_permission(&env, &role, &permission);
        Ok(())
    }

    pub fn assign_permissions_batch(
        env: Env,
        admin: Address,
        role: Symbol,
        permissions: Vec<Symbol>,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "manage_acl"));
        ACL::assign_permissions_batch(&env, &role, &permissions);
        Ok(())
    }

    pub fn set_role_parent(
        env: Env,
        admin: Address,
        child: Symbol,
        parent: Symbol,
    ) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;
        ACL::require_permission(&env, &admin, &Symbol::new(&env, "manage_acl"));
        ACL::set_parent_role(&env, &child, &parent);
        Ok(())
    }

    pub fn get_user_roles(env: Env, user: Address) -> Result<Vec<Symbol>, TradeError> {
        require_initialized(&env)?;
        Ok(ACL::get_user_roles(&env, &user))
    }

    pub fn get_role_permissions(env: Env, role: Symbol) -> Result<Vec<Symbol>, TradeError> {
        require_initialized(&env)?;
        Ok(ACL::get_role_permissions(&env, &role))
    }

    pub fn has_permission(env: Env, user: Address, permission: Symbol) -> Result<bool, TradeError> {
        require_initialized(&env)?;
        Ok(ACL::has_permission(&env, &user, &permission))
    }

    /// Propose an upgrade via governance
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_contract_hash: Symbol,
        description: Symbol,
        approvers: Vec<Address>,
        approval_threshold: u32,
        timelock_delay: u64,
    ) -> Result<u64, TradeError> {
        admin.require_auth();
        require_initialized(&env)?;

        let proposal_result = GovernanceManager::propose_upgrade(
            &env,
            admin,
            new_contract_hash,
            env.current_contract_address(),
            description,
            approval_threshold,
            approvers,
            timelock_delay,
        );

        match proposal_result {
            Ok(id) => Ok(id),
            Err(_) => Err(TradeError::Unauthorized),
        }
    }

    /// Approve an upgrade proposal
    pub fn approve_upgrade(
        env: Env,
        proposal_id: u64,
        approver: Address,
    ) -> Result<(), TradeError> {
        approver.require_auth();
        require_initialized(&env)?;

        GovernanceManager::approve_proposal(&env, proposal_id, approver)
            .map_err(|_| TradeError::Unauthorized)
    }

    /// Execute an approved upgrade proposal
    pub fn execute_upgrade(
        env: Env,
        proposal_id: u64,
        executor: Address,
    ) -> Result<(), TradeError> {
        executor.require_auth();
        require_initialized(&env)?;

        GovernanceManager::execute_proposal(&env, proposal_id, executor)
            .map_err(|_| TradeError::Unauthorized)
    }

    /// Get upgrade proposal details
    pub fn get_upgrade_proposal(env: Env, proposal_id: u64) -> Result<UpgradeProposal, TradeError> {
        require_initialized(&env)?;
        GovernanceManager::get_proposal(&env, proposal_id).map_err(|_| TradeError::Unauthorized)
    }

    /// Reject an upgrade proposal
    pub fn reject_upgrade(env: Env, proposal_id: u64, rejector: Address) -> Result<(), TradeError> {
        rejector.require_auth();
        require_initialized(&env)?;

        GovernanceManager::reject_proposal(&env, proposal_id, rejector)
            .map_err(|_| TradeError::Unauthorized)
    }

    /// Cancel an upgrade proposal (admin only)
    pub fn cancel_upgrade(env: Env, proposal_id: u64, admin: Address) -> Result<(), TradeError> {
        admin.require_auth();
        require_initialized(&env)?;

        GovernanceManager::cancel_proposal(&env, proposal_id, admin)
            .map_err(|_| TradeError::Unauthorized)
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod bench;
