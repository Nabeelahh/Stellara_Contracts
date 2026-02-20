// disaster_recovery/src/pause_control.rs
//
// Pause/Unpause Control Mechanism
// --------------------------------
// Provides a multi-level pause system:
//   Level 0 - OPERATIONAL:   All functions enabled
//   Level 1 - SOFT_PAUSE:    Non-critical writes disabled, reads still work
//   Level 2 - HARD_PAUSE:    All state-mutating operations disabled
//   Level 3 - EMERGENCY:     Only emergency recovery functions allowed

use soroban_sdk::{contracttype, Address, Env, String, symbol_short, Vec, log};
use crate::errors::DisasterRecoveryError;
use crate::monitoring::{emit_event, AlertLevel};

// ─── Storage Keys ──────────────────────────────────────────────────────────────

const PAUSE_STATE_KEY: &str        = "pause_state";
const PAUSE_HISTORY_KEY: &str      = "pause_history";
const PAUSE_GUARDIANS_KEY: &str    = "pause_guardians";
const PAUSE_COOLDOWN_KEY: &str     = "pause_cooldown";
const ADMIN_KEY: &str              = "admin";

/// Minimum ledgers between pause/unpause cycles (anti-spam)
const PAUSE_COOLDOWN_LEDGERS: u32 = 100;
/// Maximum history entries to retain
const MAX_HISTORY_ENTRIES: u32 = 50;

// ─── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PauseLevel {
    Operational = 0,
    SoftPause   = 1,
    HardPause   = 2,
    Emergency   = 3,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PauseState {
    pub level:          PauseLevel,
    pub paused_by:      Address,
    pub reason:         String,
    pub paused_at:      u32,   // ledger sequence
    pub unpause_after:  u32,   // 0 = manual unpause required
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PauseEvent {
    pub level:      PauseLevel,
    pub actor:      Address,
    pub reason:     String,
    pub ledger:     u32,
    pub is_pause:   bool,   // true = paused, false = unpaused
}

// ─── PauseController ──────────────────────────────────────────────────────────

pub struct PauseController;

impl PauseController {
    // ── Initialization ──────────────────────────────────────────────────────

    /// Initialize pause control with an admin address.
    /// Must be called once during contract deployment.
    pub fn initialize(env: &Env, admin: &Address) {
        let initial_state = PauseState {
            level:         PauseLevel::Operational,
            paused_by:     admin.clone(),
            reason:        String::from_str(env, "initialized"),
            paused_at:     env.ledger().sequence(),
            unpause_after: 0,
        };
        env.storage().instance().set(&symbol_short!("pstate"), &initial_state);
        env.storage().instance().set(&symbol_short!("admin"), admin);
        env.storage().instance().set(
            &symbol_short!("pguards"),
            &Vec::<Address>::new(env),
        );
    }

    // ── Pause Operations ────────────────────────────────────────────────────

    /// Pause the contract at the specified level.
    /// Guardians can only set SoftPause or HardPause.
    /// Admin can set any level including Emergency.
    pub fn pause(
        env:           &Env,
        caller:        &Address,
        level:         PauseLevel,
        reason:        String,
        unpause_after: u32,
    ) -> Result<(), DisasterRecoveryError> {
        caller.require_auth();

        // Validate caller permissions
        match level {
            PauseLevel::Operational => return Err(DisasterRecoveryError::InvalidParameters),
            PauseLevel::Emergency   => Self::require_admin(env, caller)?,
            _                       => Self::require_guardian_or_admin(env, caller)?,
        }

        // Check cooldown (skip for Emergency)
        if level != PauseLevel::Emergency {
            Self::check_cooldown(env)?;
        }

        // Check current state
        let current = Self::get_state(env);
        if current.level == PauseLevel::Emergency && level != PauseLevel::Emergency {
            return Err(DisasterRecoveryError::EmergencyOnlyMode);
        }
        if current.level == level {
            return Err(DisasterRecoveryError::AlreadyPaused);
        }

        let new_state = PauseState {
            level:  level.clone(),
            paused_by: caller.clone(),
            reason: reason.clone(),
            paused_at: env.ledger().sequence(),
            unpause_after,
        };

        env.storage().instance().set(&symbol_short!("pstate"), &new_state);
        Self::set_cooldown(env);
        Self::record_history(env, caller, &level, &reason, true);

        emit_event(env, "ContractPaused", AlertLevel::Critical, &format_pause_msg(env, &level, &reason));

        log!(env, "CONTRACT PAUSED | level={:?} | reason={} | by={}", level, reason, caller);
        Ok(())
    }

    /// Unpause the contract, returning it to Operational state.
    /// Only admin can unpause from Emergency. Guardians can unpause from other levels.
    pub fn unpause(
        env:    &Env,
        caller: &Address,
        reason: String,
    ) -> Result<(), DisasterRecoveryError> {
        caller.require_auth();

        let current = Self::get_state(env);

        match &current.level {
            PauseLevel::Operational => return Err(DisasterRecoveryError::ContractNotPaused),
            PauseLevel::Emergency   => Self::require_admin(env, caller)?,
            _                       => Self::require_guardian_or_admin(env, caller)?,
        }

        // Check if auto-unpause window has passed (if set)
        if current.unpause_after > 0 && env.ledger().sequence() < current.unpause_after {
            // Still allow manual unpause by admin
            Self::require_admin(env, caller)?;
        }

        let operational = PauseState {
            level:         PauseLevel::Operational,
            paused_by:     caller.clone(),
            reason:        reason.clone(),
            paused_at:     env.ledger().sequence(),
            unpause_after: 0,
        };

        env.storage().instance().set(&symbol_short!("pstate"), &operational);
        Self::set_cooldown(env);
        Self::record_history(env, caller, &PauseLevel::Operational, &reason, false);

        emit_event(env, "ContractUnpaused", AlertLevel::Warning, &reason);

        log!(env, "CONTRACT UNPAUSED | reason={} | by={}", reason, caller);
        Ok(())
    }

    // ── Guardian Management ─────────────────────────────────────────────────

    /// Add a guardian address that can trigger pause/unpause.
    pub fn add_guardian(env: &Env, admin: &Address, guardian: &Address) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let mut guardians: Vec<Address> = env.storage().instance()
            .get(&symbol_short!("pguards"))
            .unwrap_or(Vec::new(env));

        if !guardians.contains(guardian) {
            guardians.push_back(guardian.clone());
            env.storage().instance().set(&symbol_short!("pguards"), &guardians);
            log!(env, "Guardian added: {}", guardian);
        }
        Ok(())
    }

    /// Remove a guardian address.
    pub fn remove_guardian(env: &Env, admin: &Address, guardian: &Address) -> Result<(), DisasterRecoveryError> {
        admin.require_auth();
        Self::require_admin(env, admin)?;

        let guardians: Vec<Address> = env.storage().instance()
            .get(&symbol_short!("pguards"))
            .unwrap_or(Vec::new(env));

        let filtered: Vec<Address> = guardians.iter()
            .filter(|g| g != guardian)
            .collect();

        env.storage().instance().set(&symbol_short!("pguards"), &filtered);
        log!(env, "Guardian removed: {}", guardian);
        Ok(())
    }

    // ── State Queries ───────────────────────────────────────────────────────

    pub fn get_state(env: &Env) -> PauseState {
        env.storage().instance()
            .get(&symbol_short!("pstate"))
            .unwrap_or_else(|| panic!("PauseController not initialized"))
    }

    pub fn is_paused(env: &Env) -> bool {
        Self::get_state(env).level != PauseLevel::Operational
    }

    pub fn is_operational(env: &Env) -> bool {
        Self::get_state(env).level == PauseLevel::Operational
    }

    /// Assert contract is operational, returning error if paused.
    /// Use this as a guard at the top of sensitive functions.
    pub fn assert_operational(env: &Env) -> Result<(), DisasterRecoveryError> {
        let state = Self::get_state(env);
        match state.level {
            PauseLevel::Operational => Ok(()),
            PauseLevel::Emergency   => Err(DisasterRecoveryError::EmergencyOnlyMode),
            _                       => Err(DisasterRecoveryError::ContractPaused),
        }
    }

    /// Assert contract is at least SoftPause level (allows reads in soft pause).
    pub fn assert_reads_allowed(env: &Env) -> Result<(), DisasterRecoveryError> {
        let state = Self::get_state(env);
        match state.level {
            PauseLevel::Emergency => Err(DisasterRecoveryError::EmergencyOnlyMode),
            _                     => Ok(()),   // reads allowed at all other levels
        }
    }

    pub fn get_pause_history(env: &Env) -> Vec<PauseEvent> {
        env.storage().instance()
            .get(&symbol_short!("phist"))
            .unwrap_or(Vec::new(env))
    }

    // ── Internal Helpers ────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), DisasterRecoveryError> {
        let admin: Address = env.storage().instance()
            .get(&symbol_short!("admin"))
            .ok_or(DisasterRecoveryError::NotAdmin)?;
        if &admin != caller {
            return Err(DisasterRecoveryError::NotAdmin);
        }
        Ok(())
    }

    fn require_guardian_or_admin(env: &Env, caller: &Address) -> Result<(), DisasterRecoveryError> {
        if Self::require_admin(env, caller).is_ok() {
            return Ok(());
        }
        let guardians: Vec<Address> = env.storage().instance()
            .get(&symbol_short!("pguards"))
            .unwrap_or(Vec::new(env));
        if guardians.contains(caller) {
            return Ok(());
        }
        Err(DisasterRecoveryError::NotGuardian)
    }

    fn check_cooldown(env: &Env) -> Result<(), DisasterRecoveryError> {
        let cooldown_until: u32 = env.storage().instance()
            .get(&symbol_short!("pcooldown"))
            .unwrap_or(0);
        if env.ledger().sequence() < cooldown_until {
            return Err(DisasterRecoveryError::PauseCooldownActive);
        }
        Ok(())
    }

    fn set_cooldown(env: &Env) {
        let until = env.ledger().sequence() + PAUSE_COOLDOWN_LEDGERS;
        env.storage().instance().set(&symbol_short!("pcooldown"), &until);
    }

    fn record_history(env: &Env, actor: &Address, level: &PauseLevel, reason: &String, is_pause: bool) {
        let mut history: Vec<PauseEvent> = env.storage().instance()
            .get(&symbol_short!("phist"))
            .unwrap_or(Vec::new(env));

        history.push_back(PauseEvent {
            level:    level.clone(),
            actor:    actor.clone(),
            reason:   reason.clone(),
            ledger:   env.ledger().sequence(),
            is_pause,
        });

        // Trim to max entries (keep last N)
        while history.len() > MAX_HISTORY_ENTRIES {
            history.pop_front();
        }

        env.storage().instance().set(&symbol_short!("phist"), &history);
    }
}

fn format_pause_msg(env: &Env, level: &PauseLevel, reason: &String) -> String {
    // Simple concatenation for on-chain string
    reason.clone()
}