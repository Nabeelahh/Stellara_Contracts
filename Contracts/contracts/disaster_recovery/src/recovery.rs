// disaster_recovery/src/recovery.rs
//
// Recovery Procedures
// --------------------
// Implements structured recovery actions for different failure types.
// Recovery proposals require multi-sig approval (quorum) before execution.
//
// Recovery action types:
//   StateRollback   - Roll back contract state to a known-good checkpoint
//   FundsRescue     - Rescue stuck/at-risk funds to a safe address
//   AdminRotation   - Replace compromised admin key
//   DataRepair      - Repair corrupted on-chain data fields
//   ContractUpgrade - Upgrade contract WASM in emergency (requires full quorum)
//   ResetCircuits   - Reset all circuit breakers after incident resolution

use soroban_sdk::{
    contracttype, Address, BytesN, Env, Map, String, Vec, symbol_short, log,
};
use crate::errors::DisasterRecoveryError;
use crate::monitoring::{emit_event, AlertLevel};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Ledgers before a recovery proposal expires
const RECOVERY_PROPOSAL_TTL: u32 = 2_000;
/// Required consecutive council approvals for standard recovery
const STANDARD_QUORUM: u32 = 2;
/// Required consecutive council approvals for high-impact recovery (upgrade, admin rotation)
const HIGH_IMPACT_QUORUM: u32 = 3;
/// Maximum concurrent open proposals
const MAX_OPEN_PROPOSALS: u32 = 5;

// ─── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryActionType {
    StateRollback,
    FundsRescue,
    AdminRotation,
    DataRepair,
    ContractUpgrade,
    ResetCircuits,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Pending,    // Awaiting approvals
    Approved,   // Quorum reached, ready to execute
    Executed,   // Successfully executed
    Expired,    // Passed TTL without execution
    Rejected,   // Explicitly rejected (any council member can reject)
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RecoveryProposal {
    pub id:             u32,
    pub action_type:    RecoveryActionType,
    pub proposer:       Address,
    pub description:    String,
    pub target_address: Option<Address>,    // For FundsRescue / AdminRotation
    pub data:           Vec<u32>,           // Generic payload (action-specific)
    pub proposed_at:    u32,
    pub expires_at:     u32,
    pub status:         ProposalStatus,
    pub approvals:      Vec<Address>,
    pub required_quorum: u32,
    pub executed_at:    u32,
    pub executed_by:    Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RecoveryCouncil {
    pub members:        Vec<Address>,
    pub admin:          Address,
}

// ─── RecoveryManager ──────────────────────────────────────────────────────────

pub struct RecoveryManager;

impl RecoveryManager {
    // ── Initialization ────────────────────────────────────────────────────────

    pub fn initialize(env: &Env, admin: &Address, council_members: Vec<Address>) {
        let council = RecoveryCouncil {
            members: council_members,
            admin:   admin.clone(),
        };
        env.storage().instance().set(&symbol_short!("rcouncil"), &council);
        env.storage().instance().set(&symbol_short!("prop_nonce"), &0u32);
        env.storage().instance().set(
            &symbol_short!("proposals"),
            &Map::<u32, RecoveryProposal>::new(env),
        );
        log!(env, "RecoveryManager initialized");
    }

    // ── Proposal Lifecycle ────────────────────────────────────────────────────

    /// Submit a new recovery proposal. Council members and admin can propose.
    pub fn propose(
        env:            &Env,
        proposer:       &Address,
        action_type:    RecoveryActionType,
        description:    String,
        target_address: Option<Address>,
        data:           Vec<u32>,
    ) -> Result<u32, DisasterRecoveryError> {
        proposer.require_auth();
        Self::require_council_or_admin(env, proposer)?;

        let mut proposals = Self::get_proposals(env);
        let open_count = proposals.iter()
            .filter(|(_, p)| p.status == ProposalStatus::Pending)
            .count();

        if open_count >= MAX_OPEN_PROPOSALS as usize {
            return Err(DisasterRecoveryError::RecoveryAlreadyActive);
        }

        let quorum = Self::required_quorum_for(&action_type);
        let nonce: u32 = env.storage().instance()
            .get(&symbol_short!("prop_nonce"))
            .unwrap_or(0) + 1;

        let current = env.ledger().sequence();
        let proposal = RecoveryProposal {
            id:              nonce,
            action_type:     action_type.clone(),
            proposer:        proposer.clone(),
            description:     description.clone(),
            target_address,
            data,
            proposed_at:     current,
            expires_at:      current + RECOVERY_PROPOSAL_TTL,
            status:          ProposalStatus::Pending,
            approvals:       Vec::new(env),
            required_quorum: quorum,
            executed_at:     0,
            executed_by:     None,
        };

        proposals.set(nonce, proposal);
        env.storage().instance().set(&symbol_short!("proposals"), &proposals);
        env.storage().instance().set(&symbol_short!("prop_nonce"), &nonce);

        emit_event(env, "RecoveryProposed", AlertLevel::Warning, &description);
        log!(env, "Recovery proposal #{} created: {:?}", nonce, action_type);

        Ok(nonce)
    }

    /// Approve a pending recovery proposal. Each council member can approve once.
    pub fn approve(
        env:         &Env,
        approver:    &Address,
        proposal_id: u32,
    ) -> Result<ProposalStatus, DisasterRecoveryError> {
        approver.require_auth();
        Self::require_council_or_admin(env, approver)?;

        let mut proposals = Self::get_proposals(env);
        let mut proposal = proposals.get(proposal_id)
            .ok_or(DisasterRecoveryError::RecoveryNotActive)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(DisasterRecoveryError::RecoveryAlreadyExecuted);
        }

        if env.ledger().sequence() > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            proposals.set(proposal_id, proposal);
            env.storage().instance().set(&symbol_short!("proposals"), &proposals);
            return Err(DisasterRecoveryError::RecoveryExpired);
        }

        // Prevent double-approval
        if proposal.approvals.contains(approver) {
            return Ok(proposal.status);
        }

        proposal.approvals.push_back(approver.clone());

        if proposal.approvals.len() >= proposal.required_quorum {
            proposal.status = ProposalStatus::Approved;
            emit_event(env, "RecoveryApproved", AlertLevel::Warning,
                &String::from_str(env, "quorum_reached"));
            log!(env, "Recovery proposal #{} APPROVED (quorum reached)", proposal_id);
        }

        let status = proposal.status.clone();
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&symbol_short!("proposals"), &proposals);

        Ok(status)
    }

    /// Reject a pending proposal. Any council member or admin can reject.
    pub fn reject(
        env:         &Env,
        rejecter:    &Address,
        proposal_id: u32,
    ) -> Result<(), DisasterRecoveryError> {
        rejecter.require_auth();
        Self::require_council_or_admin(env, rejecter)?;

        let mut proposals = Self::get_proposals(env);
        let mut proposal = proposals.get(proposal_id)
            .ok_or(DisasterRecoveryError::RecoveryNotActive)?;

        if proposal.status != ProposalStatus::Pending {
            return Err(DisasterRecoveryError::RecoveryAlreadyExecuted);
        }

        proposal.status = ProposalStatus::Rejected;
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&symbol_short!("proposals"), &proposals);

        emit_event(env, "RecoveryRejected", AlertLevel::Info,
            &String::from_str(env, "proposal_rejected"));
        log!(env, "Recovery proposal #{} REJECTED by {}", proposal_id, rejecter);
        Ok(())
    }

    /// Execute an approved recovery proposal.
    /// The executor triggers the actual recovery action.
    pub fn execute(
        env:         &Env,
        executor:    &Address,
        proposal_id: u32,
    ) -> Result<RecoveryActionType, DisasterRecoveryError> {
        executor.require_auth();
        Self::require_council_or_admin(env, executor)?;

        let mut proposals = Self::get_proposals(env);
        let mut proposal = proposals.get(proposal_id)
            .ok_or(DisasterRecoveryError::RecoveryNotActive)?;

        match proposal.status {
            ProposalStatus::Approved => {}
            ProposalStatus::Executed => return Err(DisasterRecoveryError::RecoveryAlreadyExecuted),
            ProposalStatus::Expired  => return Err(DisasterRecoveryError::RecoveryExpired),
            _                        => return Err(DisasterRecoveryError::InsufficientQuorum),
        }

        if env.ledger().sequence() > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            proposals.set(proposal_id, proposal);
            env.storage().instance().set(&symbol_short!("proposals"), &proposals);
            return Err(DisasterRecoveryError::RecoveryWindowClosed);
        }

        let action_type = proposal.action_type.clone();

        // Perform the action-specific logic
        Self::dispatch_recovery(env, &proposal)?;

        proposal.status      = ProposalStatus::Executed;
        proposal.executed_at = env.ledger().sequence();
        proposal.executed_by = Some(executor.clone());

        proposals.set(proposal_id, proposal.clone());
        env.storage().instance().set(&symbol_short!("proposals"), &proposals);

        emit_event(env, "RecoveryExecuted", AlertLevel::Warning, &proposal.description);
        log!(env, "Recovery proposal #{} EXECUTED | action={:?}", proposal_id, action_type);

        // Record execution in audit log
        Self::append_audit(env, proposal_id, executor, &action_type);

        Ok(action_type)
    }

    // ── Recovery Action Dispatch ───────────────────────────────────────────────

    /// Internal dispatcher — performs the actual recovery action.
    /// Each arm can be expanded with contract-specific logic.
    fn dispatch_recovery(env: &Env, proposal: &RecoveryProposal) -> Result<(), DisasterRecoveryError> {
        match &proposal.action_type {
            RecoveryActionType::ResetCircuits => {
                // Reset all circuit breakers to CLOSED state
                // Actual circuit state clearing handled via circuit_breaker module
                let circuits: Map<String, crate::circuit_breaker::CircuitStatus> =
                    env.storage().instance()
                        .get(&symbol_short!("circuits"))
                        .unwrap_or(Map::new(env));

                let mut reset_circuits: Map<String, crate::circuit_breaker::CircuitStatus> = Map::new(env);
                for (id, mut status) in circuits.iter() {
                    status.state           = crate::circuit_breaker::CircuitState::Closed;
                    status.window_value    = 0;
                    status.window_start    = env.ledger().sequence();
                    status.consecutive_ok  = 0;
                    reset_circuits.set(id, status);
                }
                env.storage().instance().set(&symbol_short!("circuits"), &reset_circuits);
                log!(env, "All circuits reset to CLOSED state");
            }

            RecoveryActionType::AdminRotation => {
                // Replace admin with the target_address from the proposal
                if let Some(new_admin) = &proposal.target_address {
                    env.storage().instance().set(&symbol_short!("admin"), new_admin);
                    log!(env, "Admin rotated to: {}", new_admin);
                } else {
                    return Err(DisasterRecoveryError::RecoveryActionInvalid);
                }
            }

            RecoveryActionType::StateRollback => {
                // Load a stored checkpoint and restore state
                // Checkpoint key is encoded in proposal.data[0] as checkpoint ID
                if proposal.data.is_empty() {
                    return Err(DisasterRecoveryError::RecoveryActionInvalid);
                }
                let checkpoint_id = proposal.data.get(0).unwrap();
                Self::restore_checkpoint(env, checkpoint_id)?;
                log!(env, "State rolled back to checkpoint #{}", checkpoint_id);
            }

            RecoveryActionType::FundsRescue => {
                // Mark funds for rescue — actual token transfer is done by
                // the integrating contract using the approved rescue address
                if proposal.target_address.is_none() {
                    return Err(DisasterRecoveryError::RecoveryActionInvalid);
                }
                env.storage().instance().set(
                    &symbol_short!("rescue_addr"),
                    &proposal.target_address,
                );
                log!(env, "Funds rescue target set: {:?}", proposal.target_address);
            }

            RecoveryActionType::DataRepair => {
                // Clear corrupted storage keys listed in proposal.data
                // data = list of storage key hashes (simplified as u32 IDs here)
                log!(env, "Data repair executed | {} keys targeted", proposal.data.len());
                // Domain-specific repair logic goes here
            }

            RecoveryActionType::ContractUpgrade => {
                // Contract upgrade requires the new WASM hash to be pre-uploaded
                // data[0] encodes a reference to the approved upgrade hash
                // Actual upgrade is triggered via env.deployer().update_current_contract_wasm()
                // but must be called by the integrating contract's upgrade entry point.
                log!(env, "Upgrade recovery action recorded — integrating contract must finalize");
            }
        }

        Ok(())
    }

    // ── Checkpoint System ─────────────────────────────────────────────────────

    /// Save a named checkpoint of key state values.
    /// Call this periodically (e.g., after large operations) to support rollback.
    pub fn save_checkpoint(
        env:           &Env,
        checkpoint_id: u32,
        state_hash:    BytesN<32>,  // hash of current contract state
        description:   String,
    ) {
        #[contracttype]
        #[derive(Clone)]
        struct Checkpoint {
            id:          u32,
            state_hash:  BytesN<32>,
            description: String,
            ledger:      u32,
        }

        let cp = Checkpoint {
            id: checkpoint_id,
            state_hash,
            description,
            ledger: env.ledger().sequence(),
        };

        let key = (symbol_short!("cp"), checkpoint_id);
        env.storage().instance().set(&key, &cp);
        log!(env, "Checkpoint #{} saved at ledger {}", checkpoint_id, env.ledger().sequence());
    }

    fn restore_checkpoint(env: &Env, _checkpoint_id: u32) -> Result<(), DisasterRecoveryError> {
        // In practice, each integrating contract implements its own restore logic.
        // The checkpoint provides the hash proof; actual field restoration is domain-specific.
        // This function serves as the hook that a recovery proposal calls.
        Ok(())
    }

    // ── Audit Log ─────────────────────────────────────────────────────────────

    fn append_audit(env: &Env, proposal_id: u32, executor: &Address, action: &RecoveryActionType) {
        #[contracttype]
        #[derive(Clone)]
        struct AuditEntry {
            proposal_id: u32,
            executor:    Address,
            ledger:      u32,
        }

        let mut audit: Vec<AuditEntry> = env.storage().instance()
            .get(&symbol_short!("audit"))
            .unwrap_or(Vec::new(env));

        audit.push_back(AuditEntry {
            proposal_id,
            executor: executor.clone(),
            ledger:   env.ledger().sequence(),
        });

        // Keep last 100 entries
        while audit.len() > 100 {
            audit.pop_front();
        }

        env.storage().instance().set(&symbol_short!("audit"), &audit);
    }

    // ── Council Management ────────────────────────────────────────────────────

    pub fn add_council_member(
        env:    &Env,
        admin:  &Address,
        member: &Address,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut council: RecoveryCouncil = env.storage().instance()
            .get(&symbol_short!("rcouncil"))
            .ok_or(DisasterRecoveryError::InternalError)?;

        if !council.members.contains(member) {
            council.members.push_back(member.clone());
            env.storage().instance().set(&symbol_short!("rcouncil"), &council);
        }
        Ok(())
    }

    pub fn remove_council_member(
        env:    &Env,
        admin:  &Address,
        member: &Address,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut council: RecoveryCouncil = env.storage().instance()
            .get(&symbol_short!("rcouncil"))
            .ok_or(DisasterRecoveryError::InternalError)?;

        let filtered: Vec<Address> = council.members.iter()
            .filter(|m| m != member)
            .collect();
        council.members = filtered;
        env.storage().instance().set(&symbol_short!("rcouncil"), &council);
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn get_proposal(env: &Env, proposal_id: u32) -> Option<RecoveryProposal> {
        Self::get_proposals(env).get(proposal_id)
    }

    pub fn list_pending_proposals(env: &Env) -> Vec<RecoveryProposal> {
        let proposals = Self::get_proposals(env);
        let mut pending = Vec::new(env);
        for (_, p) in proposals.iter() {
            if p.status == ProposalStatus::Pending || p.status == ProposalStatus::Approved {
                pending.push_back(p);
            }
        }
        pending
    }

    pub fn get_council(env: &Env) -> Option<RecoveryCouncil> {
        env.storage().instance().get(&symbol_short!("rcouncil"))
    }

    // ── Internal Helpers ──────────────────────────────────────────────────────

    fn get_proposals(env: &Env) -> Map<u32, RecoveryProposal> {
        env.storage().instance()
            .get(&symbol_short!("proposals"))
            .unwrap_or(Map::new(env))
    }

    fn required_quorum_for(action: &RecoveryActionType) -> u32 {
        match action {
            RecoveryActionType::ContractUpgrade | RecoveryActionType::AdminRotation => HIGH_IMPACT_QUORUM,
            _ => STANDARD_QUORUM,
        }
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), DisasterRecoveryError> {
        let council: RecoveryCouncil = env.storage().instance()
            .get(&symbol_short!("rcouncil"))
            .ok_or(DisasterRecoveryError::NotAdmin)?;
        if &council.admin != caller {
            return Err(DisasterRecoveryError::NotAdmin);
        }
        Ok(())
    }

    fn require_council_or_admin(env: &Env, caller: &Address) -> Result<(), DisasterRecoveryError> {
        let council: RecoveryCouncil = env.storage().instance()
            .get(&symbol_short!("rcouncil"))
            .ok_or(DisasterRecoveryError::NotRecoveryCouncil)?;

        if &council.admin == caller || council.members.contains(caller) {
            return Ok(());
        }
        Err(DisasterRecoveryError::NotRecoveryCouncil)
    }
}