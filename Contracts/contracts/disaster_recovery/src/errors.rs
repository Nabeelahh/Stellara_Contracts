// disaster_recovery/src/errors.rs

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DisasterRecoveryError {
    // Authorization Errors
    Unauthorized = 1,
    NotAdmin = 2,
    NotGuardian = 3,
    NotRecoveryCouncil = 4,

    // Pause Errors
    ContractPaused = 10,
    ContractNotPaused = 11,
    AlreadyPaused = 12,
    PauseCooldownActive = 13,
    EmergencyOnlyMode = 14,

    // Circuit Breaker Errors
    CircuitBreakerOpen = 20,
    CircuitBreakerAlreadyOpen = 21,
    CircuitBreakerAlreadyClosed = 22,
    ThresholdNotReached = 23,
    InvalidThreshold = 24,
    CircuitBreakerCooldown = 25,

    // Recovery Errors
    RecoveryAlreadyActive = 30,
    RecoveryNotActive = 31,
    RecoveryExpired = 32,
    InsufficientQuorum = 33,
    RecoveryActionInvalid = 34,
    RecoveryWindowClosed = 35,
    RecoveryAlreadyExecuted = 36,

    // Monitoring Errors
    AlertAlreadyActive = 40,
    AlertNotFound = 41,
    InvalidAlertLevel = 42,
    MonitoringDisabled = 43,

    // General Errors
    InvalidParameters = 50,
    OperationFailed = 51,
    DataCorruption = 52,
    InternalError = 53,
}