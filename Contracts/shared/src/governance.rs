use soroban_sdk::{contracttype, Address, Env, Vec, Symbol, symbol_short};
use crate::events::{
    EventEmitter, ProposalCreatedEvent, ProposalApprovedEvent, ProposalRejectedEvent,
    ProposalExecutedEvent, ProposalCancelledEvent,
};

/// Upgrade proposal that must be approved via governance
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    pub id: u64,
    pub proposer: Address,
    pub new_contract_hash: Symbol,
    pub target_contract: Address,
    pub description: Symbol,
    pub approval_threshold: u32,           // e.g., 2 of 3
    pub approvers: Vec<Address>,
    pub approvals_count: u32,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub execution_time: u64,               // Timelock: when it can be executed
    pub executed: bool,
}

/// Status of an upgrade proposal
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProposalStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Executed = 3,
    Cancelled = 4,
}

/// Governance role
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GovernanceRole {
    Admin = 0,        // Can propose upgrades and cancel
    Approver = 1,     // Can approve/reject proposals
    Executor = 2,     // Can execute approved proposals (after timelock)
}

/// Governance error codes
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GovernanceError {
    Unauthorized = 2001,
    InvalidProposal = 2002,
    InsufficientApprovals = 2003,
    TimelockNotExpired = 2004,
    ProposalNotApproved = 2005,
    InvalidThreshold = 2006,
    DuplicateApproval = 2007,
    ProposalNotFound = 2008,
}

impl From<GovernanceError> for soroban_sdk::Error {
    fn from(error: GovernanceError) -> Self {
        soroban_sdk::Error::from_contract_error(error as u32)
    }
}

impl From<soroban_sdk::Error> for GovernanceError {
    fn from(_error: soroban_sdk::Error) -> Self {
        GovernanceError::Unauthorized
    }
}

pub struct GovernanceManager;

impl GovernanceManager {
    /// Validate that an address has a specific role
    pub fn require_role(env: &Env, address: &Address, required_role: GovernanceRole) {
        let roles_key = symbol_short!("roles");
        let role_map: soroban_sdk::Map<Address, GovernanceRole> = env
            .storage()
            .persistent()
            .get(&roles_key)
            .unwrap_or_else(|| soroban_sdk::Map::new(env));

        let user_role = role_map.get(address.clone()).unwrap_or(GovernanceRole::Executor);
        
        if user_role > required_role {
            panic!("UNAUTH");
        }
    }

    /// Create a new upgrade proposal
    pub fn propose_upgrade(
        env: &Env,
        proposer: Address,
        new_contract_hash: Symbol,
        target_contract: Address,
        description: Symbol,
        approval_threshold: u32,
        approvers: Vec<Address>,
        timelock_delay: u64,
    ) -> Result<u64, GovernanceError> {
        // Validate proposer is admin
        Self::require_role(env, &proposer, GovernanceRole::Admin);

        // Validate threshold
        if approval_threshold == 0 || approval_threshold > approvers.len() as u32 {
            return Err(GovernanceError::InvalidThreshold);
        }

        // Get next proposal ID
        let proposal_counter_key = symbol_short!("prop_cnt");
        let proposal_id: u64 = env
            .storage()
            .persistent()
            .get(&proposal_counter_key)
            .unwrap_or(0u64);

        let next_id = proposal_id + 1;

        // Clone values for event emission before moving into proposal
        let event_proposer = proposer.clone();
        let event_new_contract_hash = new_contract_hash.clone();
        let event_target_contract = target_contract.clone();
        let event_description = description.clone();

        let proposal = UpgradeProposal {
            id: next_id,
            proposer,
            new_contract_hash,
            target_contract,
            description,
            approval_threshold,
            approvers,
            approvals_count: 0,
            status: ProposalStatus::Pending,
            created_at: env.ledger().timestamp(),
            execution_time: env.ledger().timestamp() + timelock_delay,
            executed: false,
        };

        // Store proposal
        let proposals_key = symbol_short!("props");
        let mut proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .unwrap_or_else(|| soroban_sdk::Map::new(env));

        proposals.set(next_id, proposal);
        env.storage().persistent().set(&proposals_key, &proposals);

        // Update counter
        env.storage()
            .persistent()
            .set(&proposal_counter_key, &next_id);

        // Emit proposal created event
        EventEmitter::proposal_created(env, ProposalCreatedEvent {
            proposal_id: next_id,
            proposer: event_proposer,
            new_contract_hash: event_new_contract_hash,
            target_contract: event_target_contract,
            description: event_description,
            approval_threshold,
            timelock_delay,
            timestamp: env.ledger().timestamp(),
        });

        Ok(next_id)
    }

    /// Approve a proposal
    pub fn approve_proposal(
        env: &Env,
        proposal_id: u64,
        approver: Address,
    ) -> Result<(), GovernanceError> {
        // Validate approver has permission
        Self::require_role(env, &approver, GovernanceRole::Approver);

        let proposals_key = symbol_short!("props");
        let mut proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .ok_or(GovernanceError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Validate proposal status
        if proposal.status != ProposalStatus::Pending {
            return Err(GovernanceError::InvalidProposal);
        }

        // Validate approver is in the list
        if !proposal.approvers.iter().any(|a| a == approver) {
            return Err(GovernanceError::Unauthorized);
        }

        // Check for duplicate approval
        let approvals_key = symbol_short!("apprv");
        let mut approvals: soroban_sdk::Map<(u64, Address), bool> = env
            .storage()
            .persistent()
            .get(&approvals_key)
            .unwrap_or_else(|| soroban_sdk::Map::new(env));

        if approvals.get((proposal_id, approver.clone())).is_some() {
            return Err(GovernanceError::DuplicateApproval);
        }

        // Record approval
        approvals.set((proposal_id, approver.clone()), true);
        env.storage().persistent().set(&approvals_key, &approvals);

        // Increment approval count
        proposal.approvals_count += 1;

        // Check if threshold reached
        if proposal.approvals_count >= proposal.approval_threshold {
            proposal.status = ProposalStatus::Approved;
        }

        let current_approvals = proposal.approvals_count;
        let threshold = proposal.approval_threshold;

        proposals.set(proposal_id, proposal);
        env.storage().persistent().set(&proposals_key, &proposals);

        // Emit proposal approved event
        EventEmitter::proposal_approved(env, ProposalApprovedEvent {
            proposal_id,
            approver,
            current_approvals,
            threshold,
            timestamp: env.ledger().timestamp(),
        });

        Ok(())
    }

    /// Execute an approved proposal (only after timelock expires)
    pub fn execute_proposal(
        env: &Env,
        proposal_id: u64,
        executor: Address,
    ) -> Result<(), GovernanceError> {
        // Validate executor has permission
        Self::require_role(env, &executor, GovernanceRole::Executor);

        let proposals_key = symbol_short!("props");
        let mut proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .ok_or(GovernanceError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Validate proposal is approved
        if proposal.status != ProposalStatus::Approved {
            return Err(GovernanceError::ProposalNotApproved);
        }

        // Check timelock expiration
        if env.ledger().timestamp() < proposal.execution_time {
            return Err(GovernanceError::TimelockNotExpired);
        }

        // Mark as executed
        proposal.executed = true;
        proposal.status = ProposalStatus::Executed;

        let new_contract_hash = proposal.new_contract_hash.clone();

        proposals.set(proposal_id, proposal);
        env.storage().persistent().set(&proposals_key, &proposals);

        // Emit proposal executed event
        EventEmitter::proposal_executed(env, ProposalExecutedEvent {
            proposal_id,
            executor,
            new_contract_hash,
            timestamp: env.ledger().timestamp(),
        });

        Ok(())
    }

    /// Reject a proposal
    pub fn reject_proposal(
        env: &Env,
        proposal_id: u64,
        rejector: Address,
    ) -> Result<(), GovernanceError> {
        Self::require_role(env, &rejector, GovernanceRole::Approver);

        let proposals_key = symbol_short!("props");
        let mut proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .ok_or(GovernanceError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(GovernanceError::InvalidProposal);
        }

        proposal.status = ProposalStatus::Rejected;
        proposals.set(proposal_id, proposal);
        env.storage().persistent().set(&proposals_key, &proposals);

        // Emit proposal rejected event
        EventEmitter::proposal_rejected(env, ProposalRejectedEvent {
            proposal_id,
            rejector,
            timestamp: env.ledger().timestamp(),
        });

        Ok(())
    }

    /// Cancel a proposal (admin only)
    pub fn cancel_proposal(
        env: &Env,
        proposal_id: u64,
        admin: Address,
    ) -> Result<(), GovernanceError> {
        Self::require_role(env, &admin, GovernanceRole::Admin);

        let proposals_key = symbol_short!("props");
        let mut proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .ok_or(GovernanceError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if proposal.executed {
            return Err(GovernanceError::InvalidProposal);
        }

        proposal.status = ProposalStatus::Cancelled;
        proposals.set(proposal_id, proposal);
        env.storage().persistent().set(&proposals_key, &proposals);

        // Emit proposal cancelled event
        EventEmitter::proposal_cancelled(env, ProposalCancelledEvent {
            proposal_id,
            cancelled_by: admin,
            timestamp: env.ledger().timestamp(),
        });

        Ok(())
    }

    /// Get a proposal by ID
    pub fn get_proposal(
        env: &Env,
        proposal_id: u64,
    ) -> Result<UpgradeProposal, GovernanceError> {
        let proposals_key = symbol_short!("props");
        let proposals: soroban_sdk::Map<u64, UpgradeProposal> = env
            .storage()
            .persistent()
            .get(&proposals_key)
            .ok_or(GovernanceError::ProposalNotFound)?;

        proposals
            .get(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)
    }
}
