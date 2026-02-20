// disaster_recovery_contract/src/lib.rs
//
// Stellara Disaster Recovery Contract
// =====================================
// Top-level contract that integrates:
//   - PauseController   (pause / unpause mechanisms)
//   - CircuitBreakerRegistry (circuit breakers)
//   - RecoveryManager   (multi-sig recovery proposals)
//   - Monitoring        (alert emission & storage)
//
// This contract can be deployed standalone or the modules can be embedded
// into an existing Stellara contract.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, Address, BytesN, Env, String, Vec,
};

use disaster_recovery::{
    // Pause
    PauseController, PauseLevel, PauseState, PauseEvent,
    // Circuit Breakers
    CircuitBreakerRegistry, CircuitConfig, CircuitStatus, CircuitState, CircuitType,
    // Recovery
    RecoveryManager, RecoveryActionType, RecoveryCouncil,
    RecoveryProposal, ProposalStatus,
    // Monitoring
    monitoring::{self, Alert, AlertLevel, MonitoringConfig},
    // Errors
    DisasterRecoveryError,
};

// ─── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct DisasterRecoveryContract;

#[contractimpl]
impl DisasterRecoveryContract {

    // ══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ══════════════════════════════════════════════════════════════════════════

    /// Initialize the disaster recovery system.
    /// Must be called once by the deployer.
    pub fn initialize(
        env:             Env,
        admin:           Address,
        council_members: Vec<Address>,
    ) {
        admin.require_auth();
        PauseController::initialize(&env, &admin);
        RecoveryManager::initialize(&env, &admin, council_members);
        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Warning,
            max_stored_alerts: 200,
        });
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PAUSE / UNPAUSE
    // ══════════════════════════════════════════════════════════════════════════

    /// Pause the contract at a specified level.
    ///
    /// # Arguments
    /// * `level`        — SoftPause | HardPause | Emergency
    /// * `reason`       — Human-readable reason string
    /// * `unpause_after`— Ledger sequence after which auto-unpause is allowed (0 = manual only)
    pub fn pause(
        env:           Env,
        caller:        Address,
        level:         PauseLevel,
        reason:        String,
        unpause_after: u32,
    ) -> Result<(), DisasterRecoveryError> {
        PauseController::pause(&env, &caller, level, reason, unpause_after)
    }

    /// Unpause the contract, returning it to operational state.
    pub fn unpause(
        env:    Env,
        caller: Address,
        reason: String,
    ) -> Result<(), DisasterRecoveryError> {
        PauseController::unpause(&env, &caller, reason)
    }

    /// Add a guardian that can trigger pause (but not emergency pause).
    pub fn add_pause_guardian(
        env:      Env,
        admin:    Address,
        guardian: Address,
    ) -> Result<(), DisasterRecoveryError> {
        PauseController::add_guardian(&env, &admin, &guardian)
    }

    /// Remove a pause guardian.
    pub fn remove_pause_guardian(
        env:      Env,
        admin:    Address,
        guardian: Address,
    ) -> Result<(), DisasterRecoveryError> {
        PauseController::remove_guardian(&env, &admin, &guardian)
    }

    /// Returns the current pause state.
    pub fn get_pause_state(env: Env) -> PauseState {
        PauseController::get_state(&env)
    }

    /// Returns true if the contract is paused at any level.
    pub fn is_paused(env: Env) -> bool {
        PauseController::is_paused(&env)
    }

    /// Returns pause/unpause history (last 50 events).
    pub fn get_pause_history(env: Env) -> Vec<PauseEvent> {
        PauseController::get_pause_history(&env)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CIRCUIT BREAKERS
    // ══════════════════════════════════════════════════════════════════════════

    /// Register a new circuit breaker.
    pub fn register_circuit(
        env:        Env,
        admin:      Address,
        circuit_id: String,
        config:     CircuitConfig,
    ) -> Result<(), DisasterRecoveryError> {
        CircuitBreakerRegistry::register_circuit(&env, &admin, circuit_id, config)
    }

    /// Record an observation for a circuit. Returns error if circuit is OPEN.
    ///
    /// Use this as a guard at the start of any operation the circuit protects:
    /// ```
    /// contract.observe_circuit(env, "transfer_volume".into(), amount)?;
    /// ```
    pub fn observe_circuit(
        env:        Env,
        circuit_id: String,
        value:      i128,
    ) -> Result<(), DisasterRecoveryError> {
        CircuitBreakerRegistry::observe(&env, &circuit_id, value)
    }

    /// Record the result of a HALF_OPEN probe attempt.
    pub fn record_probe(
        env:        Env,
        circuit_id: String,
        success:    bool,
    ) -> Result<(), DisasterRecoveryError> {
        CircuitBreakerRegistry::record_probe_result(&env, &circuit_id, success)
    }

    /// Manually force a circuit OPEN (admin only).
    pub fn force_open_circuit(
        env:        Env,
        admin:      Address,
        circuit_id: String,
        reason:     String,
    ) -> Result<(), DisasterRecoveryError> {
        CircuitBreakerRegistry::force_open(&env, &admin, &circuit_id, reason)
    }

    /// Manually force a circuit CLOSED (admin only — use with care).
    pub fn force_close_circuit(
        env:        Env,
        admin:      Address,
        circuit_id: String,
    ) -> Result<(), DisasterRecoveryError> {
        CircuitBreakerRegistry::force_close(&env, &admin, &circuit_id)
    }

    /// Returns status of a specific circuit.
    pub fn get_circuit_status(env: Env, circuit_id: String) -> Option<CircuitStatus> {
        CircuitBreakerRegistry::get_circuit_status(&env, &circuit_id)
    }

    /// Returns IDs of all currently OPEN circuits.
    pub fn list_open_circuits(env: Env) -> Vec<String> {
        CircuitBreakerRegistry::list_open_circuits(&env)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RECOVERY PROCEDURES
    // ══════════════════════════════════════════════════════════════════════════

    /// Submit a recovery proposal.
    ///
    /// # Recovery action types:
    /// - `StateRollback`   — Roll back to a previous checkpoint
    /// - `FundsRescue`     — Designate a rescue address for stuck funds
    /// - `AdminRotation`   — Replace the admin key
    /// - `DataRepair`      — Repair corrupted storage fields
    /// - `ContractUpgrade` — Emergency contract upgrade
    /// - `ResetCircuits`   — Reset all open circuit breakers
    pub fn propose_recovery(
        env:            Env,
        proposer:       Address,
        action_type:    RecoveryActionType,
        description:    String,
        target_address: Option<Address>,
        data:           Vec<u32>,
    ) -> Result<u32, DisasterRecoveryError> {
        RecoveryManager::propose(&env, &proposer, action_type, description, target_address, data)
    }

    /// Approve a pending recovery proposal.
    pub fn approve_recovery(
        env:         Env,
        approver:    Address,
        proposal_id: u32,
    ) -> Result<ProposalStatus, DisasterRecoveryError> {
        RecoveryManager::approve(&env, &approver, proposal_id)
    }

    /// Reject a recovery proposal.
    pub fn reject_recovery(
        env:         Env,
        rejecter:    Address,
        proposal_id: u32,
    ) -> Result<(), DisasterRecoveryError> {
        RecoveryManager::reject(&env, &rejecter, proposal_id)
    }

    /// Execute an approved recovery proposal.
    pub fn execute_recovery(
        env:         Env,
        executor:    Address,
        proposal_id: u32,
    ) -> Result<RecoveryActionType, DisasterRecoveryError> {
        RecoveryManager::execute(&env, &executor, proposal_id)
    }

    /// Save a state checkpoint for potential rollback.
    pub fn save_checkpoint(
        env:           Env,
        checkpoint_id: u32,
        state_hash:    BytesN<32>,
        description:   String,
    ) {
        RecoveryManager::save_checkpoint(&env, checkpoint_id, state_hash, description)
    }

    /// Retrieve a specific recovery proposal.
    pub fn get_recovery_proposal(env: Env, proposal_id: u32) -> Option<RecoveryProposal> {
        RecoveryManager::get_proposal(&env, proposal_id)
    }

    /// List all pending or approved recovery proposals.
    pub fn list_pending_recoveries(env: Env) -> Vec<RecoveryProposal> {
        RecoveryManager::list_pending_proposals(&env)
    }

    /// Get the current recovery council configuration.
    pub fn get_council(env: Env) -> Option<RecoveryCouncil> {
        RecoveryManager::get_council(&env)
    }

    /// Add a council member (admin only).
    pub fn add_council_member(
        env:    Env,
        admin:  Address,
        member: Address,
    ) -> Result<(), DisasterRecoveryError> {
        RecoveryManager::add_council_member(&env, &admin, &member)
    }

    /// Remove a council member (admin only).
    pub fn remove_council_member(
        env:    Env,
        admin:  Address,
        member: Address,
    ) -> Result<(), DisasterRecoveryError> {
        RecoveryManager::remove_council_member(&env, &admin, &member)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MONITORING
    // ══════════════════════════════════════════════════════════════════════════

    /// Query stored alerts.
    ///
    /// # Arguments
    /// * `min_level`       — Filter to at least this severity (None = all)
    /// * `unresolved_only` — If true, exclude resolved alerts
    pub fn get_alerts(
        env:            Env,
        min_level:      Option<AlertLevel>,
        unresolved_only: bool,
    ) -> Vec<Alert> {
        monitoring::get_alerts(&env, min_level, unresolved_only)
    }

    /// Mark an alert as resolved.
    pub fn resolve_alert(env: Env, admin: Address, alert_id: u32) {
        monitoring::resolve_alert(&env, &admin, alert_id)
    }

    /// Update monitoring configuration.
    pub fn configure_monitoring(
        env:    Env,
        admin:  Address,
        config: MonitoringConfig,
    ) {
        monitoring::configure(&env, &admin, config)
    }

    /// Returns true if there are active unresolved Critical or Fatal alerts.
    pub fn has_active_critical_alerts(env: Env) -> bool {
        monitoring::has_active_critical_alerts(&env)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // COMBINED HEALTH CHECK
    // ══════════════════════════════════════════════════════════════════════════

    /// Single-call health summary for off-chain monitoring agents.
    pub fn health_check(env: Env) -> HealthStatus {
        let pause_state    = PauseController::get_state(&env);
        let open_circuits  = CircuitBreakerRegistry::list_open_circuits(&env);
        let pending_recovery = RecoveryManager::list_pending_proposals(&env);
        let critical_alerts  = monitoring::has_active_critical_alerts(&env);

        HealthStatus {
            is_operational:    pause_state.level == PauseLevel::Operational,
            pause_level:       pause_state.level,
            open_circuit_count: open_circuits.len(),
            open_circuits,
            pending_recovery_count: pending_recovery.len(),
            has_critical_alerts: critical_alerts,
        }
    }
}

// ─── HealthStatus ─────────────────────────────────────────────────────────────

use soroban_sdk::contracttype;

#[contracttype]
#[derive(Clone, Debug)]
pub struct HealthStatus {
    pub is_operational:         bool,
    pub pause_level:            PauseLevel,
    pub open_circuit_count:     u32,
    pub open_circuits:          Vec<String>,
    pub pending_recovery_count: u32,
    pub has_critical_alerts:    bool,
}