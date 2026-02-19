//! Shared utilities and types for Stellara contracts

use soroban_sdk::{contracttype, String};

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractConfig {
    pub admin: String,
    pub version: u32,
    pub is_paused: bool,
}

pub mod events;
pub mod fees;
pub mod governance;
pub mod oracle;

/// Standard contract error codes
pub mod errors {
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const INVALID_AMOUNT: &str = "INVALID_AMOUNT";
    pub const PAUSED: &str = "PAUSED";
    pub const ALREADY_EXISTS: &str = "ALREADY_EXISTS";
}
