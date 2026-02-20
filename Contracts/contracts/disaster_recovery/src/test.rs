// disaster_recovery/src/tests.rs
//
// Test Suite for Disaster Recovery Modules
// ==========================================

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, Env, String, Vec, vec,
};

use crate::{
    circuit_breaker::{CircuitBreakerRegistry, CircuitConfig, CircuitState, CircuitType},
    errors::DisasterRecoveryError,
    monitoring::{self, AlertLevel, MonitoringConfig},
    pause_control::{PauseController, PauseLevel},
    recovery::{RecoveryActionType, RecoveryManager, ProposalStatus},
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn setup_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    (env, admin)
}

fn make_council(env: &Env, n: usize) -> Vec<Address> {
    let mut v = Vec::new(env);
    for _ in 0..n {
        v.push_back(Address::generate(env));
    }
    v
}

fn str(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

fn circuit_id(env: &Env) -> String {
    str(env, "transfer_volume")
}

fn make_circuit_config(env: &Env, circuit_type: CircuitType, threshold: i128) -> CircuitConfig {
    CircuitConfig {
        circuit_type,
        threshold,
        window_ledgers:   100,
        cooldown_ledgers: 500,
        auto_reset:       false,
        enabled:          true,
    }
}

// ─── PauseController Tests ────────────────────────────────────────────────────

mod pause_tests {
    use super::*;

    #[test]
    fn test_initialize_creates_operational_state() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let state = PauseController::get_state(&env);
        assert_eq!(state.level, PauseLevel::Operational);
        assert!(!PauseController::is_paused(&env));
    }

    #[test]
    fn test_pause_soft_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let result = PauseController::pause(
            &env, &admin, PauseLevel::SoftPause,
            str(&env, "Maintenance"), 0,
        );
        assert!(result.is_ok());

        let state = PauseController::get_state(&env);
        assert_eq!(state.level, PauseLevel::SoftPause);
        assert!(PauseController::is_paused(&env));
    }

    #[test]
    fn test_pause_hard_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let result = PauseController::pause(
            &env, &admin, PauseLevel::HardPause,
            str(&env, "Security incident"), 0,
        );
        assert!(result.is_ok());
        assert_eq!(PauseController::get_state(&env).level, PauseLevel::HardPause);
    }

    #[test]
    fn test_pause_emergency() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let result = PauseController::pause(
            &env, &admin, PauseLevel::Emergency,
            str(&env, "Critical exploit detected"), 0,
        );
        assert!(result.is_ok());
        assert_eq!(PauseController::get_state(&env).level, PauseLevel::Emergency);
    }

    #[test]
    fn test_unpause_returns_to_operational() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        PauseController::pause(&env, &admin, PauseLevel::SoftPause, str(&env, "test"), 0).unwrap();
        assert!(PauseController::is_paused(&env));

        // Advance past cooldown
        env.ledger().with_mut(|l| l.sequence_number += 200);

        PauseController::unpause(&env, &admin, str(&env, "All clear")).unwrap();
        assert!(!PauseController::is_paused(&env));
        assert_eq!(PauseController::get_state(&env).level, PauseLevel::Operational);
    }

    #[test]
    fn test_unpause_when_not_paused_returns_error() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let result = PauseController::unpause(&env, &admin, str(&env, "test"));
        assert_eq!(result, Err(DisasterRecoveryError::ContractNotPaused));
    }

    #[test]
    fn test_guardian_can_soft_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let guardian = Address::generate(&env);
        PauseController::add_guardian(&env, &admin, &guardian).unwrap();

        let result = PauseController::pause(
            &env, &guardian, PauseLevel::SoftPause,
            str(&env, "Guardian triggered"), 0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_guardian_cannot_emergency_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let guardian = Address::generate(&env);
        PauseController::add_guardian(&env, &admin, &guardian).unwrap();

        let result = PauseController::pause(
            &env, &guardian, PauseLevel::Emergency,
            str(&env, "Attempt"), 0,
        );
        assert_eq!(result, Err(DisasterRecoveryError::NotAdmin));
    }

    #[test]
    fn test_non_guardian_cannot_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        let random = Address::generate(&env);
        let result = PauseController::pause(
            &env, &random, PauseLevel::SoftPause,
            str(&env, "attempt"), 0,
        );
        assert_eq!(result, Err(DisasterRecoveryError::NotGuardian));
    }

    #[test]
    fn test_assert_operational_fails_when_paused() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        PauseController::pause(&env, &admin, PauseLevel::HardPause, str(&env, "test"), 0).unwrap();
        let result = PauseController::assert_operational(&env);
        assert_eq!(result, Err(DisasterRecoveryError::ContractPaused));
    }

    #[test]
    fn test_pause_history_recorded() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        PauseController::pause(&env, &admin, PauseLevel::SoftPause, str(&env, "test"), 0).unwrap();
        env.ledger().with_mut(|l| l.sequence_number += 200);
        PauseController::unpause(&env, &admin, str(&env, "clear")).unwrap();

        let history = PauseController::get_pause_history(&env);
        assert!(history.len() >= 2);
    }

    #[test]
    fn test_cooldown_prevents_rapid_pause() {
        let (env, admin) = setup_env();
        PauseController::initialize(&env, &admin);

        PauseController::pause(&env, &admin, PauseLevel::SoftPause, str(&env, "test"), 0).unwrap();
        env.ledger().with_mut(|l| l.sequence_number += 10); // < cooldown
        PauseController::unpause(&env, &admin, str(&env, "clear")).unwrap();

        // Try to pause again within cooldown window
        let result = PauseController::pause(
            &env, &admin, PauseLevel::SoftPause, str(&env, "again"), 0,
        );
        assert_eq!(result, Err(DisasterRecoveryError::PauseCooldownActive));
    }
}

// ─── CircuitBreaker Tests ─────────────────────────────────────────────────────

mod circuit_tests {
    use super::*;

    fn init(env: &Env, admin: &Address) {
        env.storage().instance().set(&soroban_sdk::symbol_short!("admin"), admin);
    }

    #[test]
    fn test_register_and_observe_circuit() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let config = make_circuit_config(&env, CircuitType::Volume, 10);
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        // 9 observations — should be fine
        for _ in 0..9 {
            assert!(CircuitBreakerRegistry::observe(&env, &id, 1).is_ok());
        }
    }

    #[test]
    fn test_circuit_trips_at_threshold() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let config = make_circuit_config(&env, CircuitType::Volume, 5);
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        for _ in 0..4 {
            CircuitBreakerRegistry::observe(&env, &id, 1).unwrap();
        }

        // 5th observation should trip the circuit
        let result = CircuitBreakerRegistry::observe(&env, &id, 1);
        assert_eq!(result, Err(DisasterRecoveryError::CircuitBreakerOpen));

        assert!(CircuitBreakerRegistry::is_circuit_open(&env, &id));
    }

    #[test]
    fn test_open_circuit_rejects_all_observations() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let config = make_circuit_config(&env, CircuitType::Volume, 1);
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        let _ = CircuitBreakerRegistry::observe(&env, &id, 1);

        let result = CircuitBreakerRegistry::observe(&env, &id, 1);
        assert_eq!(result, Err(DisasterRecoveryError::CircuitBreakerOpen));
    }

    #[test]
    fn test_circuit_transitions_to_half_open_after_cooldown() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let mut config = make_circuit_config(&env, CircuitType::Volume, 1);
        config.cooldown_ledgers = 100;
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        let _ = CircuitBreakerRegistry::observe(&env, &id, 1); // Trip

        // Advance past cooldown
        env.ledger().with_mut(|l| l.sequence_number += 101);

        // Should transition to HALF_OPEN and allow this probe
        let result = CircuitBreakerRegistry::observe(&env, &id, 1);
        assert!(result.is_ok());

        let status = CircuitBreakerRegistry::get_circuit_status(&env, &id).unwrap();
        assert_eq!(status.state, CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_closes_after_successful_probes() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let mut config = make_circuit_config(&env, CircuitType::Volume, 1);
        config.cooldown_ledgers = 100;
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        let _ = CircuitBreakerRegistry::observe(&env, &id, 1); // Trip
        env.ledger().with_mut(|l| l.sequence_number += 101);
        let _ = CircuitBreakerRegistry::observe(&env, &id, 1); // → HALF_OPEN

        // 3 successful probes → CLOSED
        for _ in 0..3 {
            CircuitBreakerRegistry::record_probe_result(&env, &id, true).unwrap();
        }

        let status = CircuitBreakerRegistry::get_circuit_status(&env, &id).unwrap();
        assert_eq!(status.state, CircuitState::Closed);
    }

    #[test]
    fn test_failed_probe_reopens_circuit() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let mut config = make_circuit_config(&env, CircuitType::Volume, 1);
        config.cooldown_ledgers = 100;
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        let _ = CircuitBreakerRegistry::observe(&env, &id, 1);
        env.ledger().with_mut(|l| l.sequence_number += 101);
        let _ = CircuitBreakerRegistry::observe(&env, &id, 1); // → HALF_OPEN

        CircuitBreakerRegistry::record_probe_result(&env, &id, false).unwrap();

        let status = CircuitBreakerRegistry::get_circuit_status(&env, &id).unwrap();
        assert_eq!(status.state, CircuitState::Open);
    }

    #[test]
    fn test_force_open_and_close() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = circuit_id(&env);
        let config = make_circuit_config(&env, CircuitType::Volume, 1000);
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        CircuitBreakerRegistry::force_open(&env, &admin, &id, str(&env, "manual")).unwrap();
        assert!(CircuitBreakerRegistry::is_circuit_open(&env, &id));

        CircuitBreakerRegistry::force_close(&env, &admin, &id).unwrap();
        assert!(!CircuitBreakerRegistry::is_circuit_open(&env, &id));
    }

    #[test]
    fn test_liquidity_circuit_triggers_below_threshold() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id = str(&env, "liquidity_guard");
        let config = make_circuit_config(&env, CircuitType::Liquidity, 1_000_000);
        CircuitBreakerRegistry::register_circuit(&env, &admin, id.clone(), config).unwrap();

        // High liquidity — OK
        assert!(CircuitBreakerRegistry::observe(&env, &id, 5_000_000).is_ok());

        // Low liquidity — should trip
        let result = CircuitBreakerRegistry::observe(&env, &id, 500_000);
        assert_eq!(result, Err(DisasterRecoveryError::CircuitBreakerOpen));
    }

    #[test]
    fn test_list_open_circuits() {
        let (env, admin) = setup_env();
        init(&env, &admin);

        let id1 = str(&env, "circuit_a");
        let id2 = str(&env, "circuit_b");

        CircuitBreakerRegistry::register_circuit(
            &env, &admin, id1.clone(),
            make_circuit_config(&env, CircuitType::Volume, 1),
        ).unwrap();
        CircuitBreakerRegistry::register_circuit(
            &env, &admin, id2.clone(),
            make_circuit_config(&env, CircuitType::Volume, 1000),
        ).unwrap();

        let _ = CircuitBreakerRegistry::observe(&env, &id1, 1); // trip circuit_a
        let _ = CircuitBreakerRegistry::observe(&env, &id2, 1); // circuit_b still fine

        let open = CircuitBreakerRegistry::list_open_circuits(&env);
        assert_eq!(open.len(), 1);
        assert_eq!(open.get(0).unwrap(), id1);
    }
}

// ─── RecoveryManager Tests ────────────────────────────────────────────────────

mod recovery_tests {
    use super::*;

    fn init(env: &Env, admin: &Address, n_members: usize) -> Vec<Address> {
        let council = make_council(env, n_members);
        RecoveryManager::initialize(env, admin, council.clone());
        council
    }

    #[test]
    fn test_propose_recovery() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "Reset after incident"),
            None,
            Vec::new(&env),
        ).unwrap();

        assert_eq!(id, 1);
        let proposal = RecoveryManager::get_proposal(&env, id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Pending);
    }

    #[test]
    fn test_approve_reaches_quorum() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        // Standard quorum = 2
        let s1 = RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        assert_eq!(s1, ProposalStatus::Pending);

        let s2 = RecoveryManager::approve(&env, &council.get(1).unwrap(), id).unwrap();
        assert_eq!(s2, ProposalStatus::Approved);
    }

    #[test]
    fn test_execute_approved_proposal() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        RecoveryManager::approve(&env, &council.get(1).unwrap(), id).unwrap();

        let action = RecoveryManager::execute(&env, &council.get(0).unwrap(), id).unwrap();
        assert_eq!(action, RecoveryActionType::ResetCircuits);

        let proposal = RecoveryManager::get_proposal(&env, id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    #[test]
    fn test_cannot_execute_without_quorum() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        // Only 1 approval — quorum is 2

        let result = RecoveryManager::execute(&env, &council.get(0).unwrap(), id);
        assert_eq!(result, Err(DisasterRecoveryError::InsufficientQuorum));
    }

    #[test]
    fn test_reject_proposal() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        RecoveryManager::reject(&env, &council.get(1).unwrap(), id).unwrap();
        let proposal = RecoveryManager::get_proposal(&env, id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_expired_proposal_cannot_execute() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        RecoveryManager::approve(&env, &council.get(1).unwrap(), id).unwrap();

        // Advance past TTL (2000 ledgers)
        env.ledger().with_mut(|l| l.sequence_number += 3000);

        let result = RecoveryManager::execute(&env, &council.get(0).unwrap(), id);
        assert_eq!(result, Err(DisasterRecoveryError::RecoveryWindowClosed));
    }

    #[test]
    fn test_admin_rotation_requires_high_quorum() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 4);
        let new_admin = Address::generate(&env);

        let id = RecoveryManager::propose(
            &env, &admin,
            RecoveryActionType::AdminRotation,
            str(&env, "Rotate compromised admin"),
            Some(new_admin.clone()),
            Vec::new(&env),
        ).unwrap();

        let proposal = RecoveryManager::get_proposal(&env, id).unwrap();
        assert_eq!(proposal.required_quorum, 3); // HIGH_IMPACT_QUORUM

        // 2 approvals — not enough
        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        RecoveryManager::approve(&env, &council.get(1).unwrap(), id).unwrap();
        let result = RecoveryManager::execute(&env, &council.get(0).unwrap(), id);
        assert_eq!(result, Err(DisasterRecoveryError::InsufficientQuorum));

        // 3rd approval — now enough
        RecoveryManager::approve(&env, &council.get(2).unwrap(), id).unwrap();
        let action = RecoveryManager::execute(&env, &council.get(0).unwrap(), id).unwrap();
        assert_eq!(action, RecoveryActionType::AdminRotation);
    }

    #[test]
    fn test_cannot_double_approve() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        let id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "test"),
            None,
            Vec::new(&env),
        ).unwrap();

        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap();
        RecoveryManager::approve(&env, &council.get(0).unwrap(), id).unwrap(); // double — ignored

        let proposal = RecoveryManager::get_proposal(&env, id).unwrap();
        assert_eq!(proposal.approvals.len(), 1); // still only 1 unique approval
    }

    #[test]
    fn test_list_pending_proposals() {
        let (env, admin) = setup_env();
        let council = init(&env, &admin, 3);

        RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits, str(&env, "p1"), None, Vec::new(&env),
        ).unwrap();
        RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::DataRepair, str(&env, "p2"), None, Vec::new(&env),
        ).unwrap();

        let pending = RecoveryManager::list_pending_proposals(&env);
        assert_eq!(pending.len(), 2);
    }
}

// ─── Monitoring Tests ─────────────────────────────────────────────────────────

mod monitoring_tests {
    use super::*;

    #[test]
    fn test_emit_and_retrieve_alert() {
        let (env, admin) = setup_env();

        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Warning,
            max_stored_alerts: 200,
        });

        monitoring::emit_event(&env, "TestEvent", AlertLevel::Critical, &str(&env, "test message"));

        let alerts = monitoring::get_alerts(&env, None, false);
        assert!(alerts.len() >= 1);
    }

    #[test]
    fn test_below_threshold_not_stored() {
        let (env, admin) = setup_env();

        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Warning,
            max_stored_alerts: 200,
        });

        // Info < Warning threshold — should not be persisted
        monitoring::emit_event(&env, "InfoEvent", AlertLevel::Info, &str(&env, "low priority"));
        let alerts = monitoring::get_alerts(&env, None, false);
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_resolve_alert() {
        let (env, admin) = setup_env();

        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Info,
            max_stored_alerts: 200,
        });

        monitoring::emit_event(&env, "Evt", AlertLevel::Critical, &str(&env, "msg"));
        let alerts = monitoring::get_alerts(&env, None, false);
        let alert_id = alerts.get(0).unwrap().id;

        monitoring::resolve_alert(&env, &admin, alert_id);

        let unresolved = monitoring::get_alerts(&env, None, true);
        assert_eq!(unresolved.len(), 0);
    }

    #[test]
    fn test_has_active_critical_alerts() {
        let (env, admin) = setup_env();

        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Info,
            max_stored_alerts: 200,
        });

        assert!(!monitoring::has_active_critical_alerts(&env));

        monitoring::emit_event(&env, "Crit", AlertLevel::Critical, &str(&env, "crisis"));
        assert!(monitoring::has_active_critical_alerts(&env));
    }
}

// ─── Integration Tests ────────────────────────────────────────────────────────

mod integration_tests {
    use super::*;

    /// Full disaster scenario: circuit trips → emergency pause → recovery proposal → resolution
    #[test]
    fn test_full_disaster_recovery_flow() {
        let (env, admin) = setup_env();
        env.storage().instance().set(&soroban_sdk::symbol_short!("admin"), &admin);

        let council = make_council(&env, 3);
        RecoveryManager::initialize(&env, &admin, council.clone());
        PauseController::initialize(&env, &admin);
        monitoring::configure(&env, &admin, MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Info,
            max_stored_alerts: 200,
        });

        // 1. Register a circuit breaker
        let id = str(&env, "exploit_guard");
        CircuitBreakerRegistry::register_circuit(
            &env, &admin, id.clone(),
            CircuitConfig {
                circuit_type:     CircuitType::Volume,
                threshold:        5,
                window_ledgers:   100,
                cooldown_ledgers: 500,
                auto_reset:       false,
                enabled:          true,
            },
        ).unwrap();

        // 2. Simulate attack — circuit trips
        for i in 0..5 {
            let result = CircuitBreakerRegistry::observe(&env, &id, 1);
            if i < 4 {
                assert!(result.is_ok(), "Should be OK on observation {}", i);
            } else {
                assert_eq!(result, Err(DisasterRecoveryError::CircuitBreakerOpen));
            }
        }
        assert!(CircuitBreakerRegistry::is_circuit_open(&env, &id));

        // 3. Admin triggers emergency pause
        PauseController::pause(
            &env, &admin, PauseLevel::Emergency,
            str(&env, "Exploit detected - circuit tripped"), 0,
        ).unwrap();
        assert_eq!(PauseController::get_state(&env).level, PauseLevel::Emergency);

        // 4. Council proposes ResetCircuits recovery
        let proposal_id = RecoveryManager::propose(
            &env, &council.get(0).unwrap(),
            RecoveryActionType::ResetCircuits,
            str(&env, "Reset circuits after patch"),
            None,
            Vec::new(&env),
        ).unwrap();

        // 5. Council approves
        RecoveryManager::approve(&env, &council.get(0).unwrap(), proposal_id).unwrap();
        RecoveryManager::approve(&env, &council.get(1).unwrap(), proposal_id).unwrap();

        // 6. Execute recovery (resets all circuits)
        RecoveryManager::execute(&env, &council.get(0).unwrap(), proposal_id).unwrap();
        assert!(!CircuitBreakerRegistry::is_circuit_open(&env, &id));

        // 7. Admin unpauses
        PauseController::unpause(&env, &admin, str(&env, "Incident resolved")).unwrap();
        assert!(!PauseController::is_paused(&env));

        // Verify final state
        assert_eq!(PauseController::get_state(&env).level, PauseLevel::Operational);
        assert_eq!(
            RecoveryManager::get_proposal(&env, proposal_id).unwrap().status,
            ProposalStatus::Executed,
        );
    }
}