// disaster_recovery/src/monitoring.rs
//
// Monitoring & Alert System
// --------------------------
// Provides on-chain event emission and alert state tracking for disaster
// recovery triggers. Consumed by off-chain indexers / monitoring services.

use soroban_sdk::{contracttype, Address, Env, Map, String, Vec, symbol_short, log, vec};

// ─── Alert Levels ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum AlertLevel {
    Info     = 0,
    Warning  = 1,
    Critical = 2,
    Fatal    = 3,
}

// ─── Alert Record ──────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub struct Alert {
    pub id:         u32,
    pub event_name: String,
    pub level:      AlertLevel,
    pub message:    String,
    pub ledger:     u32,
    pub resolved:   bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MonitoringConfig {
    pub enabled:               bool,
    /// Minimum alert level that gets persisted on-chain (lower levels events only)
    pub persist_threshold:     AlertLevel,
    /// Maximum alerts stored on-chain
    pub max_stored_alerts:     u32,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Emit a monitoring event. This writes to the Soroban event log (consumed
/// by indexers) and optionally persists a record in contract storage.
pub fn emit_event(env: &Env, event_name: &str, level: AlertLevel, message: &String) {
    // Always emit the event to the transaction event log
    env.events().publish(
        (symbol_short!("dr_alert"), symbol_short!("level")),
        (String::from_str(env, event_name), level.clone(), message.clone()),
    );

    // Persist in storage if at or above the configured threshold
    let config = get_config(env);
    if !config.enabled {
        return;
    }
    if level >= config.persist_threshold {
        persist_alert(env, event_name, level, message, config.max_stored_alerts);
    }
}

/// Mark an alert as resolved.
pub fn resolve_alert(env: &Env, admin: &Address, alert_id: u32) {
    admin.require_auth();
    let mut alerts = get_stored_alerts(env);
    if let Some(mut alert) = alerts.get(alert_id) {
        alert.resolved = true;
        alerts.set(alert_id, alert);
        env.storage().instance().set(&symbol_short!("alerts"), &alerts);
        log!(env, "Alert #{} resolved by {}", alert_id, admin);
    }
}

/// Update monitoring configuration.
pub fn configure(env: &Env, admin: &Address, config: MonitoringConfig) {
    admin.require_auth();
    env.storage().instance().set(&symbol_short!("mon_cfg"), &config);
}

/// Query stored alerts, optionally filtered by minimum level.
pub fn get_alerts(env: &Env, min_level: Option<AlertLevel>, unresolved_only: bool) -> Vec<Alert> {
    let alerts = get_stored_alerts(env);
    let mut result = Vec::new(env);

    for (_, alert) in alerts.iter() {
        if unresolved_only && alert.resolved {
            continue;
        }
        if let Some(ref ml) = min_level {
            if &alert.level < ml {
                continue;
            }
        }
        result.push_back(alert);
    }
    result
}

/// Get only unresolved critical/fatal alerts — used by circuit breaker auto-check.
pub fn has_active_critical_alerts(env: &Env) -> bool {
    let alerts = get_stored_alerts(env);
    for (_, alert) in alerts.iter() {
        if !alert.resolved && alert.level >= AlertLevel::Critical {
            return true;
        }
    }
    false
}

/// Return the monitoring configuration, or a safe default.
pub fn get_config(env: &Env) -> MonitoringConfig {
    env.storage().instance()
        .get(&symbol_short!("mon_cfg"))
        .unwrap_or(MonitoringConfig {
            enabled:           true,
            persist_threshold: AlertLevel::Warning,
            max_stored_alerts: 200,
        })
}

// ─── Internal ─────────────────────────────────────────────────────────────────

fn persist_alert(env: &Env, event_name: &str, level: AlertLevel, message: &String, max: u32) {
    let mut alerts = get_stored_alerts(env);

    let nonce: u32 = env.storage().instance()
        .get(&symbol_short!("alert_n"))
        .unwrap_or(0) + 1;

    let alert = Alert {
        id:         nonce,
        event_name: String::from_str(env, event_name),
        level,
        message:    message.clone(),
        ledger:     env.ledger().sequence(),
        resolved:   false,
    };

    alerts.set(nonce, alert);
    env.storage().instance().set(&symbol_short!("alert_n"), &nonce);

    // Trim if over limit (evict oldest by iterating — simple approach)
    if alerts.len() > max {
        // Find lowest key
        let min_key = alerts.iter().map(|(k, _)| k).min();
        if let Some(k) = min_key {
            alerts.remove(k);
        }
    }

    env.storage().instance().set(&symbol_short!("alerts"), &alerts);
}

fn get_stored_alerts(env: &Env) -> Map<u32, Alert> {
    env.storage().instance()
        .get(&symbol_short!("alerts"))
        .unwrap_or(Map::new(env))
}