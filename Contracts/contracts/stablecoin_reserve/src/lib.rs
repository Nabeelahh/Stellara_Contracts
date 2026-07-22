#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Map,
    Symbol, Vec,
};
use shared::events::{extended_topics, ReserveAssetAddedEvent, ReserveAssetUpdatedEvent};

mod custodian_integration;
mod proof_of_reserves;
mod rebalancing;
mod redemption;
mod regulatory_reporting;
mod reserve_tracking;

#[cfg(test)]
mod test;

use shared::governance::{GovernanceRole, ProposalStatus, UpgradeProposal};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ReserveError {
    Unauthorized = 3001,
    InsufficientReserves = 3002,
    InvalidAsset = 3003,
    ReserveRatioTooLow = 3004,
    RebalancingRequired = 3005,
    InvalidMerkleProof = 3006,
    RedemptionAmountTooSmall = 3007,
    RedemptionAmountTooLarge = 3008,
    CustodianError = 3009,
    ReportingError = 3010,
    GovernanceError = 3011,
    ProposalNotFound = 3012,
    ProposalNotActive = 3013,
    TimelockNotExpired = 3014,
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
pub struct ReserveAsset {
    pub asset_type: AssetType,
    pub amount: u128,
    pub custodian: Address,
    pub last_verified: u64,
    pub verification_hash: BytesN<32>,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AssetType {
    USD = 0,
    Treasury = 1,
    Repo = 2,
    CorporateBond = 3,
    ETF = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveSnapshot {
    pub timestamp: u64,
    pub total_reserves: u128,
    pub total_supply: u128,
    pub reserve_ratio: u64, // basis points (10000 = 100%)
    pub assets: Vec<ReserveAsset>,
    pub merkle_root: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedemptionRequest {
    pub requester: Address,
    pub amount: u128,
    pub request_time: u64,
    pub status: RedemptionStatus,
    pub processed_time: Option<u64>,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RedemptionStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Processed = 3,
}

pub struct StablecoinReserveContract;

#[contractimpl]
impl StablecoinReserveContract {
    /// Initialize the reserve management system with governance
    pub fn initialize(
        env: Env,
        admin: Address,
        approvers: Vec<Address>,
        executor: Address,
        stablecoin_address: Address,
    ) {
        // Initialize governance
        shared::governance::initialize_governance(env.clone(), admin, approvers, executor);

        // Set stablecoin address
        env.storage()
            .instance()
            .set(&symbol_short!("stblcoin"), &stablecoin_address);

        // Initialize reserve tracking
        reserve_tracking::initialize(env.clone());

        // Initialize rebalancing with 5% threshold
        rebalancing::initialize(env.clone(), 500); // 5% in basis points

        // Log initialization
        env.events().publish(
            (symbol_short!("reserve"), symbol_short!("initd")),
            (stablecoin_address, env.ledger().timestamp()),
        );
    }

    /// Add a new reserve asset
    pub fn add_reserve_asset(
        env: Env,
        asset_type: AssetType,
        amount: u128,
        custodian: Address,
        verification_hash: BytesN<32>,
    ) -> Result<(), ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        reserve_tracking::add_asset(
            env.clone(),
            asset_type,
            amount,
            custodian.clone(),
            verification_hash,
        )?;

        env.events().publish(
            (extended_topics::RESERVE_ASSET_ADDED,),
            ReserveAssetAddedEvent {
                asset: custodian.clone(),
                target_allocation: 0,
                added_by: env.invoker(),
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Update reserve asset amount
    pub fn update_reserve_asset(
        env: Env,
        asset_index: u32,
        new_amount: u128,
        verification_hash: BytesN<32>,
    ) -> Result<(), ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        reserve_tracking::update_asset(env.clone(), asset_index, new_amount, verification_hash.clone())?;

        env.events().publish(
            (extended_topics::RESERVE_ASSET_UPDATED,),
            ReserveAssetUpdatedEvent {
                asset: env.current_contract_address(),
                new_allocation: asset_index,
                updated_by: env.invoker(),
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Generate daily proof of reserves
    pub fn generate_proof_of_reserves(env: Env) -> Result<BytesN<32>, ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        proof_of_reserves::generate_daily_proof(env.clone())
    }

    /// Verify a specific user's inclusion in the proof of reserves
    pub fn verify_user_inclusion(
        env: Env,
        user: Address,
        amount: u128,
        proof: Vec<BytesN<32>>,
        leaf_index: u32,
    ) -> Result<bool, ReserveError> {
        proof_of_reserves::verify_inclusion(env.clone(), user, amount, proof, leaf_index)
    }

    /// Check if rebalancing is needed
    pub fn check_rebalancing_needed(env: Env) -> Result<bool, ReserveError> {
        rebalancing::check_rebalancing_needed(env.clone())
    }

    /// Execute rebalancing if needed
    pub fn execute_rebalancing(env: Env) -> Result<(), ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Executor) {
            return Err(ReserveError::Unauthorized);
        }

        rebalancing::execute_rebalancing(env.clone())
    }

    /// Generate regulatory report
    pub fn generate_regulatory_report(env: Env) -> Result<Symbol, ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        regulatory_reporting::generate_report(env.clone())
    }

    /// Sync with custodian API
    pub fn sync_with_custodian(env: Env, custodian: Address) -> Result<(), ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        custodian_integration::sync_with_custodian(env.clone(), custodian)
    }

    /// Request redemption for large holders ($1M+)
    pub fn request_redemption(env: Env, amount: u128) -> Result<u64, ReserveError> {
        // Check minimum amount ($1M equivalent in smallest units)
        if amount < 1_000_000_000_000 {
            // Assuming 12 decimals
            return Err(ReserveError::RedemptionAmountTooSmall);
        }

        redemption::request_redemption(env.clone(), env.invoker(), amount)
    }

    /// Process approved redemption
    pub fn process_redemption(env: Env, request_id: u64) -> Result<(), ReserveError> {
        // Check governance authorization
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Executor) {
            return Err(ReserveError::Unauthorized);
        }

        redemption::process_redemption(env.clone(), request_id)
    }

    /// Get current reserve snapshot
    pub fn get_reserve_snapshot(env: Env) -> Result<ReserveSnapshot, ReserveError> {
        reserve_tracking::get_current_snapshot(env.clone())
    }

    /// Get reserve ratio (in basis points)
    pub fn get_reserve_ratio(env: Env) -> Result<u64, ReserveError> {
        reserve_tracking::get_reserve_ratio(env.clone())
    }

    /// Get total reserves
    pub fn get_total_reserves(env: Env) -> Result<u128, ReserveError> {
        reserve_tracking::get_total_reserves(env.clone())
    }

    /// Get redemption request status
    pub fn get_redemption_status(
        env: Env,
        request_id: u64,
    ) -> Result<RedemptionRequest, ReserveError> {
        redemption::get_redemption_request(env.clone(), request_id)
    }

    /// Get all pending redemption requests
    pub fn get_pending_redemptions(env: Env) -> Result<Vec<RedemptionRequest>, ReserveError> {
        redemption::get_pending_redemptions(env.clone())
    }

    /// Propose a parameter change (governance-controlled)
    pub fn propose_parameter_change(
        env: Env,
        parameter_key: Symbol,
        new_value: u128,
    ) -> Result<u64, ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

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
            proposer: env.invoker(),
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
        proposal_id: u64,
    ) -> Result<(), ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Executor) {
            return Err(ReserveError::Unauthorized);
        }

        let proposals_key = symbol_short!("pprop");
        let mut proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ReserveError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(ReserveError::ProposalNotFound)?;

        if proposal.executed || proposal.cancelled {
            return Err(ReserveError::ProposalNotActive);
        }

        if env.ledger().timestamp() < proposal.executes_at {
            return Err(ReserveError::TimelockNotExpired);
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
        proposal_id: u64,
    ) -> Result<(), ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::Unauthorized);
        }

        let proposals_key = symbol_short!("pprop");
        let mut proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ReserveError::ProposalNotFound)?;

        let mut proposal = proposals
            .get(proposal_id)
            .ok_or(ReserveError::ProposalNotFound)?;

        if proposal.executed {
            return Err(ReserveError::ProposalNotActive);
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
    ) -> Result<ParameterProposal, ReserveError> {
        let proposals_key = symbol_short!("pprop");
        let proposals: Map<u64, ParameterProposal> = env
            .storage()
            .instance()
            .get(&proposals_key)
            .ok_or(ReserveError::ProposalNotFound)?;

        proposals
            .get(proposal_id)
            .ok_or(ReserveError::ProposalNotFound)
    }

    /// Governance functions
    pub fn propose_upgrade(
        env: Env,
        new_contract_hash: BytesN<32>,
        description: Symbol,
        approvers: Vec<Address>,
        approval_threshold: u32,
        timelock_delay: u64,
    ) -> Result<u64, ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Admin) {
            return Err(ReserveError::GovernanceError);
        }

        let proposal = UpgradeProposal {
            id: env.ledger().sequence(),
            proposer: env.invoker(),
            new_contract_hash: symbol_short!("new_hash"), // Convert bytes to symbol
            target_contract: env.current_contract_address(),
            description,
            approval_threshold,
            approvers,
            approvals_count: 0,
            status: ProposalStatus::Pending,
            created_at: env.ledger().timestamp(),
            execution_time: env.ledger().timestamp() + timelock_delay,
            executed: false,
        };

        shared::governance::create_proposal(env.clone(), proposal)
    }

    pub fn approve_upgrade(env: Env, proposal_id: u64) -> Result<(), ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Approver) {
            return Err(ReserveError::GovernanceError);
        }

        shared::governance::approve_proposal(env.clone(), proposal_id)
    }

    pub fn execute_upgrade(env: Env, proposal_id: u64) -> Result<(), ReserveError> {
        if !shared::governance::has_role(env.clone(), env.invoker(), GovernanceRole::Executor) {
            return Err(ReserveError::GovernanceError);
        }

        shared::governance::execute_proposal(env.clone(), proposal_id)
    }
}