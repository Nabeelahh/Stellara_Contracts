//! Standardized event types for on-chain action logging
//!
//! This module provides consistent event structures for off-chain indexing
//! and notification systems. All contracts should use these event types
//! to ensure reliable backend integration.

use soroban_sdk::{contracttype, Address, Symbol};

// =============================================================================
// Event Topics (standardized event names)
// =============================================================================

/// Standard event topic names for consistent indexing
pub mod topics {
    use soroban_sdk::{symbol_short, Symbol};

    // Trading events
    pub const TRADE_EXECUTED: Symbol = symbol_short!("trade");
    pub const CONTRACT_PAUSED: Symbol = symbol_short!("paused");
    pub const CONTRACT_UNPAUSED: Symbol = symbol_short!("unpause");
    pub const FEE_COLLECTED: Symbol = symbol_short!("fee");

    // Governance events
    pub const PROPOSAL_CREATED: Symbol = symbol_short!("propose");
    pub const PROPOSAL_APPROVED: Symbol = symbol_short!("approve");
    pub const PROPOSAL_REJECTED: Symbol = symbol_short!("reject");
    pub const PROPOSAL_EXECUTED: Symbol = symbol_short!("execute");
    pub const PROPOSAL_CANCELLED: Symbol = symbol_short!("cancel");

    // Social rewards events
    pub const REWARD_ADDED: Symbol = symbol_short!("reward");
    pub const REWARD_CLAIMED: Symbol = symbol_short!("claimed");

    // Token events (for reference - already implemented in token contract)
    pub const TRANSFER: Symbol = symbol_short!("transfer");
    pub const MINT: Symbol = symbol_short!("mint");
    pub const BURN: Symbol = symbol_short!("burn");
}

// =============================================================================
// Trading Events
// =============================================================================

/// Event emitted when a trade is executed
#[contracttype]
#[derive(Clone, Debug)]
pub struct TradeExecutedEvent {
    /// Unique trade identifier
    pub trade_id: u64,
    /// Address of the trader
    pub trader: Address,
    /// Trading pair symbol (e.g., "XLMUSDC")
    pub pair: Symbol,
    /// Trade amount
    pub amount: i128,
    /// Trade price
    pub price: i128,
    /// Whether this is a buy (true) or sell (false)
    pub is_buy: bool,
    /// Fee amount collected
    pub fee_amount: i128,
    /// Token used for fee payment
    pub fee_token: Address,
    /// Block timestamp when trade occurred
    pub timestamp: u64,
}

/// Event emitted when contract is paused
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractPausedEvent {
    /// Admin who paused the contract
    pub paused_by: Address,
    /// Block timestamp when paused
    pub timestamp: u64,
}

/// Event emitted when contract is unpaused
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractUnpausedEvent {
    /// Admin who unpaused the contract
    pub unpaused_by: Address,
    /// Block timestamp when unpaused
    pub timestamp: u64,
}

/// Event emitted when a fee is collected
#[contracttype]
#[derive(Clone, Debug)]
pub struct FeeCollectedEvent {
    /// Address paying the fee
    pub payer: Address,
    /// Address receiving the fee
    pub recipient: Address,
    /// Fee amount
    pub amount: i128,
    /// Token used for payment
    pub token: Address,
    /// Block timestamp
    pub timestamp: u64,
}

// =============================================================================
// Governance Events
// =============================================================================

/// Event emitted when an upgrade proposal is created
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalCreatedEvent {
    /// Unique proposal identifier
    pub proposal_id: u64,
    /// Address that created the proposal
    pub proposer: Address,
    /// Hash of the new contract to upgrade to
    pub new_contract_hash: Symbol,
    /// Contract being upgraded
    pub target_contract: Address,
    /// Description of the proposal
    pub description: Symbol,
    /// Required approvals for execution
    pub approval_threshold: u32,
    /// Timelock delay before execution (seconds)
    pub timelock_delay: u64,
    /// Block timestamp when created
    pub timestamp: u64,
}

/// Event emitted when a proposal is approved
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalApprovedEvent {
    /// Proposal identifier
    pub proposal_id: u64,
    /// Address that approved
    pub approver: Address,
    /// Current approval count after this approval
    pub current_approvals: u32,
    /// Required approvals for execution
    pub threshold: u32,
    /// Block timestamp
    pub timestamp: u64,
}

/// Event emitted when a proposal is rejected
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalRejectedEvent {
    /// Proposal identifier
    pub proposal_id: u64,
    /// Address that rejected
    pub rejector: Address,
    /// Block timestamp
    pub timestamp: u64,
}

/// Event emitted when a proposal is executed
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalExecutedEvent {
    /// Proposal identifier
    pub proposal_id: u64,
    /// Address that executed
    pub executor: Address,
    /// New contract hash that was deployed
    pub new_contract_hash: Symbol,
    /// Block timestamp
    pub timestamp: u64,
}

/// Event emitted when a proposal is cancelled
#[contracttype]
#[derive(Clone, Debug)]
pub struct ProposalCancelledEvent {
    /// Proposal identifier
    pub proposal_id: u64,
    /// Admin who cancelled
    pub cancelled_by: Address,
    /// Block timestamp
    pub timestamp: u64,
}

// =============================================================================
// Social Rewards Events
// =============================================================================

/// Event emitted when a reward is added/granted to a user
#[contracttype]
#[derive(Clone, Debug)]
pub struct RewardAddedEvent {
    /// Unique reward identifier
    pub reward_id: u64,
    /// User receiving the reward
    pub user: Address,
    /// Reward amount
    pub amount: i128,
    /// Type of reward (e.g., "referral", "engagement", "achievement")
    pub reward_type: Symbol,
    /// Optional metadata/reason for the reward
    pub reason: Symbol,
    /// Admin who granted the reward
    pub granted_by: Address,
    /// Block timestamp
    pub timestamp: u64,
}

/// Event emitted when a reward is claimed
#[contracttype]
#[derive(Clone, Debug)]
pub struct RewardClaimedEvent {
    /// Reward identifier
    pub reward_id: u64,
    /// User who claimed
    pub user: Address,
    /// Amount claimed
    pub amount: i128,
    /// Block timestamp
    pub timestamp: u64,
}

// =============================================================================
// Event Emission Helpers
// =============================================================================

use soroban_sdk::Env;

/// Helper trait for emitting standardized events
pub struct EventEmitter;

impl EventEmitter {
    /// Emit a trade executed event
    pub fn trade_executed(env: &Env, event: TradeExecutedEvent) {
        env.events().publish((topics::TRADE_EXECUTED,), event);
    }

    /// Emit a contract paused event
    pub fn contract_paused(env: &Env, event: ContractPausedEvent) {
        env.events().publish((topics::CONTRACT_PAUSED,), event);
    }

    /// Emit a contract unpaused event
    pub fn contract_unpaused(env: &Env, event: ContractUnpausedEvent) {
        env.events().publish((topics::CONTRACT_UNPAUSED,), event);
    }

    /// Emit a fee collected event
    pub fn fee_collected(env: &Env, event: FeeCollectedEvent) {
        env.events().publish((topics::FEE_COLLECTED,), event);
    }

    /// Emit a proposal created event
    pub fn proposal_created(env: &Env, event: ProposalCreatedEvent) {
        env.events().publish((topics::PROPOSAL_CREATED,), event);
    }

    /// Emit a proposal approved event
    pub fn proposal_approved(env: &Env, event: ProposalApprovedEvent) {
        env.events().publish((topics::PROPOSAL_APPROVED,), event);
    }

    /// Emit a proposal rejected event
    pub fn proposal_rejected(env: &Env, event: ProposalRejectedEvent) {
        env.events().publish((topics::PROPOSAL_REJECTED,), event);
    }

    /// Emit a proposal executed event
    pub fn proposal_executed(env: &Env, event: ProposalExecutedEvent) {
        env.events().publish((topics::PROPOSAL_EXECUTED,), event);
    }

    /// Emit a proposal cancelled event
    pub fn proposal_cancelled(env: &Env, event: ProposalCancelledEvent) {
        env.events().publish((topics::PROPOSAL_CANCELLED,), event);
    }

    /// Emit a reward added event
    pub fn reward_added(env: &Env, event: RewardAddedEvent) {
        env.events().publish((topics::REWARD_ADDED,), event);
    }

    /// Emit a reward claimed event
    pub fn reward_claimed(env: &Env, event: RewardClaimedEvent) {
        env.events().publish((topics::REWARD_CLAIMED,), event);
    }
}
