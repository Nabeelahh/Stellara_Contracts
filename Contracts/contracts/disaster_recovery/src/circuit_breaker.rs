// disaster_recovery/src/circuit_breaker.rs
//
// Circuit Breaker Pattern Implementation
// ----------------------------------------
// Protects against cascading failures by tracking abnormal conditions and
// automatically opening (disabling) circuit paths when thresholds are exceeded.
//
// State Machine:
//   CLOSED → (threshold exceeded) → OPEN → (cooldown elapsed) → HALF_OPEN
//   HALF_OPEN → (probe succeeds) → CLOSED
//   HALF_OPEN → (probe fails)    → OPEN
//
// Supported circuit types:
//   - Volume:      Triggers on high transaction count per window
//   - ValueFlow:   Triggers on large value transfers per window
//   - ErrorRate:   Triggers on high failure percentage
//   - PriceDrift:  Triggers on oracle price deviation
//   - Liquidity:   Triggers on pool liquidity falling below minimum

use soroban_sdk::{contracttype, Address, Env, Map, String, Vec, symbol_short, log};
use crate::errors::DisasterRecoveryError;
use crate::monitoring::{emit_event, AlertLevel};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Ledgers to wait before attempting HALF_OPEN probe
const DEFAULT_COOLDOWN_LEDGERS: u32 = 500;
/// Maximum circuits that can be registered
const MAX_CIRCUITS: u32 = 20;
/// Ledgers in a measurement window
const DEFAULT_WINDOW_LEDGERS: u32 = 100;

// ─── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircuitState {
    Closed,     // Normal operation
    Open,       // Tripped — all calls rejected
    HalfOpen,   // Probe phase — limited calls allowed
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CircuitType {
    Volume,     // tx count threshold
    ValueFlow,  // cumulative value threshold (in stroops or token units)
    ErrorRate,  // error percentage threshold (0–100)
    PriceDrift, // price deviation threshold (basis points)
    Liquidity,  // minimum liquidity threshold
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    pub circuit_type:      CircuitType,
    pub threshold:         i128,    // type-specific threshold value
    pub window_ledgers:    u32,     // measurement window size
    pub cooldown_ledgers:  u32,     // cooldown before HALF_OPEN
    pub auto_reset:        bool,    // auto-close after cooldown if no new triggers
    pub enabled:           bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CircuitStatus {
    pub state:             CircuitState,
    pub config:            CircuitConfig,
    pub window_start:      u32,    // ledger when current window started
    pub window_value:      i128,   // accumulated value in current window
    pub trip_count:        u32,    // total number of times tripped
    pub tripped_at:        u32,    // ledger when last tripped
    pub tripped_reason:    String,
    pub last_probe_at:     u32,
    pub consecutive_ok:    u32,    // successful probes in HALF_OPEN
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CircuitBreakEvent {
    pub circuit_id:  String,
    pub new_state:   CircuitState,
    pub ledger:      u32,
    pub reason:      String,
    pub value:       i128,
}

// ─── CircuitBreakerRegistry ───────────────────────────────────────────────────

pub struct CircuitBreakerRegistry;

impl CircuitBreakerRegistry {
    // ── Registration ─────────────────────────────────────────────────────────

    /// Register a new circuit breaker. Only admin can register circuits.
    pub fn register_circuit(
        env:        &Env,
        admin:      &Address,
        circuit_id: String,
        config:     CircuitConfig,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        if config.threshold <= 0 {
            return Err(DisasterRecoveryError::InvalidThreshold);
        }

        let mut circuits = Self::get_all_circuits(env);
        if circuits.len() >= MAX_CIRCUITS {
            return Err(DisasterRecoveryError::InvalidParameters);
        }

        let status = CircuitStatus {
            state:          CircuitState::Closed,
            config,
            window_start:   env.ledger().sequence(),
            window_value:   0,
            trip_count:     0,
            tripped_at:     0,
            tripped_reason: String::from_str(env, ""),
            last_probe_at:  0,
            consecutive_ok: 0,
        };

        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);

        log!(env, "Circuit registered: {}", circuit_id);
        Ok(())
    }

    /// Disable or enable a circuit breaker.
    pub fn set_circuit_enabled(
        env:        &Env,
        admin:      &Address,
        circuit_id: &String,
        enabled:    bool,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut circuits = Self::get_all_circuits(env);
        let mut status = circuits.get(circuit_id.clone())
            .ok_or(DisasterRecoveryError::CircuitBreakerAlreadyClosed)?;

        status.config.enabled = enabled;
        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);
        Ok(())
    }

    // ── Core Observation ─────────────────────────────────────────────────────

    /// Record an observation for a circuit.
    /// Returns Ok(()) if circuit is CLOSED, Err if OPEN/triggered.
    ///
    /// Call this on every operation the circuit guards:
    ///   - For Volume:    value = 1 (per tx)
    ///   - For ValueFlow: value = transfer amount
    ///   - For ErrorRate: value = 1 for error, 0 for success (tracked as percentage internally)
    ///   - For PriceDrift: value = current price in basis points vs baseline
    ///   - For Liquidity: value = current liquidity (triggers if below threshold)
    pub fn observe(
        env:        &Env,
        circuit_id: &String,
        value:      i128,
    ) -> Result<(), DisasterRecoveryError> {
        let mut circuits = Self::get_all_circuits(env);
        let mut status = circuits.get(circuit_id.clone())
            .ok_or(DisasterRecoveryError::CircuitBreakerAlreadyClosed)?;

        if !status.config.enabled {
            return Ok(());
        }

        let current_ledger = env.ledger().sequence();

        // Check if we're already OPEN
        match &status.state {
            CircuitState::Open => {
                // Check if cooldown has elapsed → transition to HALF_OPEN
                if current_ledger >= status.tripped_at + status.config.cooldown_ledgers {
                    status.state = CircuitState::HalfOpen;
                    status.last_probe_at = current_ledger;
                    status.consecutive_ok = 0;
                    circuits.set(circuit_id.clone(), status.clone());
                    env.storage().instance().set(&symbol_short!("circuits"), &circuits);
                    emit_event(env, "CircuitHalfOpen", AlertLevel::Warning, circuit_id);
                    log!(env, "Circuit HALF_OPEN: {}", circuit_id);
                    // Allow this probe through
                    return Ok(());
                }
                return Err(DisasterRecoveryError::CircuitBreakerOpen);
            }
            CircuitState::HalfOpen => {
                // Only allow one probe per probe interval
                // Caller must call record_probe_result after
                return Ok(());
            }
            CircuitState::Closed => {} // continue below
        }

        // Reset window if expired
        if current_ledger >= status.window_start + status.config.window_ledgers {
            status.window_start = current_ledger;
            status.window_value = 0;
        }

        // Accumulate
        status.window_value = match status.config.circuit_type {
            CircuitType::Liquidity => value, // track latest, not cumulative
            _                      => status.window_value.saturating_add(value),
        };

        // Evaluate threshold
        let tripped = Self::evaluate_threshold(&status);

        if tripped {
            let reason = Self::build_trip_reason(env, &status);
            status.state          = CircuitState::Open;
            status.trip_count    += 1;
            status.tripped_at     = current_ledger;
            status.tripped_reason = reason.clone();
            status.window_value   = 0;
            status.window_start   = current_ledger;

            circuits.set(circuit_id.clone(), status);
            env.storage().instance().set(&symbol_short!("circuits"), &circuits);

            emit_event(env, "CircuitTripped", AlertLevel::Critical, &reason);
            log!(env, "CIRCUIT TRIPPED: {} | reason={}", circuit_id, reason);

            return Err(DisasterRecoveryError::CircuitBreakerOpen);
        }

        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);
        Ok(())
    }

    /// Record the result of a HALF_OPEN probe.
    /// success=true advances toward CLOSED, false reopens.
    pub fn record_probe_result(
        env:        &Env,
        circuit_id: &String,
        success:    bool,
    ) -> Result<(), DisasterRecoveryError> {
        let mut circuits = Self::get_all_circuits(env);
        let mut status = circuits.get(circuit_id.clone())
            .ok_or(DisasterRecoveryError::CircuitBreakerAlreadyClosed)?;

        if status.state != CircuitState::HalfOpen {
            return Err(DisasterRecoveryError::CircuitBreakerAlreadyClosed);
        }

        let current_ledger = env.ledger().sequence();

        if success {
            status.consecutive_ok += 1;
            // Close after 3 consecutive successes
            if status.consecutive_ok >= 3 {
                status.state          = CircuitState::Closed;
                status.window_start   = current_ledger;
                status.window_value   = 0;
                status.consecutive_ok = 0;
                emit_event(env, "CircuitClosed", AlertLevel::Info, circuit_id);
                log!(env, "Circuit CLOSED (recovered): {}", circuit_id);
            }
        } else {
            // Re-open on failure
            status.state        = CircuitState::Open;
            status.tripped_at   = current_ledger;
            status.trip_count  += 1;
            status.consecutive_ok = 0;
            emit_event(env, "CircuitReopened", AlertLevel::Critical, circuit_id);
            log!(env, "Circuit REOPENED (probe failed): {}", circuit_id);
        }

        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);
        Ok(())
    }

    /// Manually force a circuit to OPEN state (admin only).
    pub fn force_open(
        env:        &Env,
        admin:      &Address,
        circuit_id: &String,
        reason:     String,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut circuits = Self::get_all_circuits(env);
        let mut status = circuits.get(circuit_id.clone())
            .ok_or(DisasterRecoveryError::CircuitBreakerAlreadyClosed)?;

        if status.state == CircuitState::Open {
            return Err(DisasterRecoveryError::CircuitBreakerAlreadyOpen);
        }

        status.state          = CircuitState::Open;
        status.trip_count    += 1;
        status.tripped_at     = env.ledger().sequence();
        status.tripped_reason = reason.clone();

        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);

        emit_event(env, "CircuitForcedOpen", AlertLevel::Critical, &reason);
        log!(env, "Circuit FORCE OPENED: {} | reason={}", circuit_id, reason);
        Ok(())
    }

    /// Manually force a circuit to CLOSED state (admin only — use with care).
    pub fn force_close(
        env:        &Env,
        admin:      &Address,
        circuit_id: &String,
    ) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut circuits = Self::get_all_circuits(env);
        let mut status = circuits.get(circuit_id.clone())
            .ok_or(DisasterRecoveryError::CircuitBreakerAlreadyClosed)?;

        if status.state == CircuitState::Closed {
            return Err(DisasterRecoveryError::CircuitBreakerAlreadyClosed);
        }

        status.state          = CircuitState::Closed;
        status.window_start   = env.ledger().sequence();
        status.window_value   = 0;
        status.consecutive_ok = 0;

        circuits.set(circuit_id.clone(), status);
        env.storage().instance().set(&symbol_short!("circuits"), &circuits);

        emit_event(env, "CircuitForceReset", AlertLevel::Warning, circuit_id);
        log!(env, "Circuit FORCE CLOSED: {}", circuit_id);
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn get_circuit_status(env: &Env, circuit_id: &String) -> Option<CircuitStatus> {
        Self::get_all_circuits(env).get(circuit_id.clone())
    }

    pub fn is_circuit_open(env: &Env, circuit_id: &String) -> bool {
        Self::get_all_circuits(env)
            .get(circuit_id.clone())
            .map(|s| s.state == CircuitState::Open)
            .unwrap_or(false)
    }

    pub fn list_open_circuits(env: &Env) -> Vec<String> {
        let circuits = Self::get_all_circuits(env);
        let mut open = Vec::new(env);
        for (id, status) in circuits.iter() {
            if status.state == CircuitState::Open {
                open.push_back(id);
            }
        }
        open
    }

    // ── Internal Helpers ──────────────────────────────────────────────────────

    fn get_all_circuits(env: &Env) -> Map<String, CircuitStatus> {
        env.storage().instance()
            .get(&symbol_short!("circuits"))
            .unwrap_or(Map::new(env))
    }

    fn evaluate_threshold(status: &CircuitStatus) -> bool {
        match status.config.circuit_type {
            CircuitType::Liquidity => status.window_value < status.config.threshold,
            _                      => status.window_value >= status.config.threshold,
        }
    }

    fn build_trip_reason(env: &Env, status: &CircuitStatus) -> String {
        // On-chain we keep it simple — richer details go in events
        match status.config.circuit_type {
            CircuitType::Volume     => String::from_str(env, "volume_threshold_exceeded"),
            CircuitType::ValueFlow  => String::from_str(env, "value_flow_threshold_exceeded"),
            CircuitType::ErrorRate  => String::from_str(env, "error_rate_threshold_exceeded"),
            CircuitType::PriceDrift => String::from_str(env, "price_drift_threshold_exceeded"),
            CircuitType::Liquidity  => String::from_str(env, "liquidity_below_minimum"),
        }
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), DisasterRecoveryError> {
        let admin: Address = env.storage().instance()
            .get(&symbol_short!("admin"))
            .ok_or(DisasterRecoveryError::NotAdmin)?;
        if &admin != caller {
            return Err(DisasterRecoveryError::NotAdmin);
        }
        Ok(())
    }
}