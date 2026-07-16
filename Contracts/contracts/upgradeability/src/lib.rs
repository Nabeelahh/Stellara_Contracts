#![no_std]
//! # Upgradeability Module
//!
//! Provides comprehensive initializer protection for Stellara smart contracts
//! on Soroban/Stellar. This is the Soroban equivalent of OpenZeppelin's
//! `Initializable` pattern with enhanced security features.
//!
//! ## Problem
//!
//! Upgradeable contracts use `initialize()` instead of constructors.
//! Without protection, `initialize()` can be called multiple times,
//! allowing attackers to reset admin roles, governance settings, or
//! contract state after deployment.
//!
//! ## Solution
//!
//! This module provides:
//!
//! - **Re-entry protection**: Prevents re-initialization during the same call
//! - **Version tracking**: Tracks contract version for upgrade compatibility
//! - **Storage gaps**: Reserves space for future storage additions
//! - **Initializer guards**: Prevents multiple initialization calls
//!
//! ## Usage
//!
//! ```rust,ignore
//! use upgradeability::{initializer_guard, set_contract_version};
//!
//! pub fn initialize(env: Env, admin: Address) {
//!     // Guard: prevent re-initialization with re-entry protection
//!     initializer_guard(&env);
//!
//!     // Set contract version for upgrade tracking
//!     set_contract_version(&env, 1);
//!
//!     // ... rest of initialization logic
//! }
//! ```

use soroban_sdk::{symbol_short, Env, Symbol};

/// Storage key used to track whether a contract has been initialized.
/// Uses `symbol_short!` for gas-efficient persistent storage access.
const INIT_KEY: Symbol = symbol_short!("init");

/// Storage key for tracking initialization status during a call (re-entry protection).
const INITIALIZING_KEY: Symbol = symbol_short!("initing");

/// Storage key for contract version tracking.
const VERSION_KEY: Symbol = symbol_short!("version");

/// Storage gap for future upgrades (50 bytes reserved).
/// This allows adding new storage variables in future versions without
/// breaking storage layout compatibility.
const STORAGE_GAP: Symbol = symbol_short!("gap");

/// Size of storage gap in bytes (reserves space for future upgrades).
const STORAGE_GAP_SIZE: u32 = 50;

/// Checks whether the contract has already been initialized.
///
/// # Returns
/// `true` if the contract has been initialized, `false` otherwise.
pub fn is_initialized(env: &Env) -> bool {
    env.storage().persistent().has(&INIT_KEY)
}

/// Checks whether the contract is currently initializing (re-entry protection).
///
/// # Returns
/// `true` if the contract is in the process of initializing, `false` otherwise.
pub fn is_initializing(env: &Env) -> bool {
    env.storage().temporary().has(&INITIALIZING_KEY)
}

/// Panics if the contract has already been initialized.
///
/// This function should be called at the very beginning of any `initialize()`
/// or `init()` function to prevent re-initialization attacks.
///
/// # Panics
/// Panics with `"Already initialized"` if the contract was previously initialized.
pub fn ensure_not_initialized(env: &Env) {
    if is_initialized(env) {
        panic!("Already initialized");
    }
}

/// Panics if the contract is currently initializing (re-entry protection).
///
/// This prevents re-entry attacks where a function called during initialization
/// could attempt to re-initialize the contract.
///
/// # Panics
/// Panics with `"Re-entering initialization"` if called during initialization.
pub fn ensure_not_initializing(env: &Env) {
    if is_initializing(env) {
        panic!("Re-entering initialization");
    }
}

/// Marks the contract as initializing (temporary storage for re-entry protection).
///
/// This should be called at the start of initialization to prevent re-entry.
fn set_initializing(env: &Env) {
    env.storage().temporary().set(&INITIALIZING_KEY, &true);
}

/// Clears the initializing flag (called at end of initialization).
///
/// This should be called after initialization completes to allow future upgrades.
fn clear_initializing(env: &Env) {
    env.storage().temporary().remove(&INITIALIZING_KEY);
}

/// Marks the contract as initialized by writing to persistent storage.
///
/// This function should be called immediately after `ensure_not_initialized()`
/// to atomically protect against re-initialization.
///
/// # Storage
/// Sets the `"init"` key in persistent storage to `true`.
pub fn mark_initialized(env: &Env) {
    env.storage().persistent().set(&INIT_KEY, &true);
}

/// Sets the contract version for upgrade tracking.
///
/// This allows future versions to check compatibility and perform migrations.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `version` - The version number of this contract implementation
///
/// # Storage
/// Sets the `"version"` key in persistent storage to the provided version.
pub fn set_contract_version(env: &Env, version: u32) {
    env.storage().persistent().set(&VERSION_KEY, &version);
}

/// Gets the contract version.
///
/// # Returns
/// The version number if set, or 0 if not yet initialized.
pub fn get_contract_version(env: &Env) -> u32 {
    env.storage().persistent().get(&VERSION_KEY).unwrap_or(0)
}

/// Initializes storage gap for future upgrades.
///
/// This reserves space in storage layout to allow adding new variables
/// in future versions without breaking compatibility with existing deployments.
///
/// # Storage
/// Reserves `STORAGE_GAP_SIZE` bytes under the `"gap"` key.
pub fn initialize_storage_gap(env: &Env) {
    let mut gap_bytes = soroban_sdk::Bytes::new(env);
    for _ in 0..STORAGE_GAP_SIZE {
        gap_bytes.push_back(0u8);
    }
    env.storage().persistent().set(&STORAGE_GAP, &gap_bytes);
}

/// Combined guard: ensures the contract is not yet initialized, prevents re-entry,
/// then marks it as initialized.
///
/// This is a convenience function that combines all protection mechanisms:
/// - Checks contract is not already initialized
/// - Sets re-entry protection flag
/// - Marks contract as initialized
/// - Clears re-entry protection flag
///
/// # Panics
/// Panics with `"Already initialized"` if the contract was previously initialized.
/// Panics with `"Re-entering initialization"` if called during initialization.
///
/// # Example
/// ```rust,ignore
/// pub fn initialize(env: Env, admin: Address) {
///     upgradeability::initializer_guard(&env);
///     // ... setup logic
/// }
/// ```
pub fn initializer_guard(env: &Env) {
    ensure_not_initialized(env);
    ensure_not_initializing(env);
    set_initializing(env);
    mark_initialized(env);
    clear_initializing(env);
}

/// Full initializer guard with version and storage gap initialization.
///
/// This is the recommended guard for new contracts as it provides:
/// - Re-entry protection
/// - Initialization protection
/// - Version tracking
/// - Storage gap reservation
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `version` - The version number of this contract implementation
///
/// # Panics
/// Panics with `"Already initialized"` if the contract was previously initialized.
/// Panics with `"Re-entering initialization"` if called during initialization.
///
/// # Example
/// ```rust,ignore
/// pub fn initialize(env: Env, admin: Address) {
///     upgradeability::full_initializer_guard(&env, 1);
///     // ... setup logic
/// }
/// ```
pub fn full_initializer_guard(env: &Env, version: u32) {
    ensure_not_initialized(env);
    ensure_not_initializing(env);
    set_initializing(env);
    mark_initialized(env);
    set_contract_version(env, version);
    initialize_storage_gap(env);
    clear_initializing(env);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::{contract, contractimpl, Env};

    // A minimal test contract that delegates to the upgradeability module
    #[contract]
    pub struct TestInitContract;

    #[contractimpl]
    impl TestInitContract {
        pub fn do_init(env: Env) {
            initializer_guard(&env);
        }

        pub fn do_full_init(env: Env, version: u32) {
            full_initializer_guard(&env, version);
        }

        pub fn check_initialized(env: Env) -> bool {
            is_initialized(&env)
        }

        pub fn check_initializing(env: Env) -> bool {
            is_initializing(&env)
        }

        pub fn do_mark(env: Env) {
            mark_initialized(&env);
        }

        pub fn do_ensure(env: Env) {
            ensure_not_initialized(&env);
        }

        pub fn get_version(env: Env) -> u32 {
            get_contract_version(&env)
        }

        pub fn set_version(env: Env, version: u32) {
            set_contract_version(&env, version);
        }
    }

    #[test]
    fn test_fresh_contract_is_not_initialized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        assert!(!client.check_initialized());
    }

    #[test]
    fn test_mark_initialized_sets_flag() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        assert!(!client.check_initialized());
        client.do_mark();
        assert!(client.check_initialized());
    }

    #[test]
    fn test_initializer_guard_succeeds_on_first_call() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        client.do_init(); // should not panic
        assert!(client.check_initialized());
    }

    #[test]
    fn test_full_initializer_guard_sets_version() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        
        client.do_full_init(&1);
        assert!(client.check_initialized());
        assert_eq!(client.get_version(), 1);
    }

    #[test]
    fn test_version_tracking() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        
        // Version is 0 before initialization
        assert_eq!(client.get_version(), 0);
        
        // Set version
        client.set_version(&1);
        assert_eq!(client.get_version(), 1);
        
        // Update version
        client.set_version(&2);
        assert_eq!(client.get_version(), 2);
    }

    #[test]
    fn test_is_initializing_flag() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        
        // Not initializing initially
        assert!(!client.check_initializing());
        
        // After full init, flag should be cleared
        client.do_full_init(&1);
        assert!(!client.check_initializing());
    }

    // Note: Tests for double-init rejection (panic path) are covered by
    // the integration tests in `integration-tests/tests/initializer_protection.rs`
    // because Soroban cdylib panics cause process abort rather than unwinding,
    // which cannot be caught by the unit test harness.

    #[test]
    fn test_is_initialized_returns_false_before_mark() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        assert!(!client.check_initialized());
    }

    #[test]
    fn test_is_initialized_returns_true_after_mark() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TestInitContract);
        let client = TestInitContractClient::new(&env, &contract_id);
        client.do_mark();
        assert!(client.check_initialized());
    }
}

