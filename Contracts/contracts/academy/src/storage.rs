//! Optimized storage module for Academy Vesting Contract
//!
//! Storage optimizations:
//! - Instance storage for admin, token, governance, and counter (static data)
//! - Persistent storage for individual vesting schedules with indexed access
//! - User vesting index for efficient lookups
//! - Optimized key patterns using enum-based keys

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec, symbol_short};

/// Contract version for migration tracking
const CONTRACT_VERSION: u32 = 2;

/// Storage keys using enum for type safety and efficiency
#[contracttype]
#[derive(Clone, Debug)]
pub enum AcademyDataKey {
    Init,
    Admin,
    Token,
    Governance,
    Counter,
    Schedule(u64),            // Individual schedule by ID
    UserScheduleIds(Address), // List of schedule IDs for a user
    ActiveSchedules,          // Index of active (non-claimed, non-revoked) schedules
}

/// Storage manager for academy vesting contract
pub struct AcademyStorage;

impl AcademyStorage {
    // ============ Initialization ============
    
    pub fn is_initialized(env: &Env) -> bool {
        env.storage().instance().has(&AcademyDataKey::Init)
    }
    
    pub fn set_initialized(env: &Env) {
        env.storage().instance().set(&AcademyDataKey::Init, &true);
        env.storage().instance().set(&AcademyDataKey::Counter, &0u64);
    }
    
    // ============ Version Management ============
    
    pub fn get_version(env: &Env) -> u32 {
        env.storage().instance().get(&Symbol::new(env, "version")).unwrap_or(0)
    }
    
    pub fn set_version(env: &Env, version: u32) {
        env.storage().instance().set(&Symbol::new(env, "version"), &version);
    }
    
    // ============ Admin, Token & Governance ============
    
    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().instance().set(&AcademyDataKey::Admin, admin);
    }
    
    pub fn get_admin(env: &Env) -> Option<Address> {
        env.storage().instance().get(&AcademyDataKey::Admin)
    }
    
    pub fn set_token(env: &Env, token: &Address) {
        env.storage().instance().set(&AcademyDataKey::Token, token);
    }
    
    pub fn get_token(env: &Env) -> Option<Address> {
        env.storage().instance().get(&AcademyDataKey::Token)
    }
    
    pub fn set_governance(env: &Env, governance: &Address) {
        env.storage().instance().set(&AcademyDataKey::Governance, governance);
    }
    
    pub fn get_governance(env: &Env) -> Option<Address> {
        env.storage().instance().get(&AcademyDataKey::Governance)
    }
    
    // ============ Counter ============
    
    pub fn get_counter(env: &Env) -> u64 {
        env.storage().instance().get(&AcademyDataKey::Counter).unwrap_or(0)
    }
    
    pub fn increment_counter(env: &Env) -> u64 {
        let current = Self::get_counter(env);
        let next = current + 1;
        env.storage().instance().set(&AcademyDataKey::Counter, &next);
        next
    }
    
    // ============ Schedule Storage ============
    
    /// Store individual vesting schedule with optimized key
    pub fn set_schedule<T: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, schedule_id: u64, schedule: &T) {
        let key = AcademyDataKey::Schedule(schedule_id);
        env.storage().persistent().set(&key, schedule);
    }
    
    /// Get vesting schedule by ID
    pub fn get_schedule<T: soroban_sdk::TryFromVal<Env, soroban_sdk::Val> + Clone>(env: &Env, schedule_id: u64) -> Option<T> {
        env.storage().persistent().get(&AcademyDataKey::Schedule(schedule_id))
    }
    
    /// Check if schedule exists
    pub fn has_schedule(env: &Env, schedule_id: u64) -> bool {
        env.storage().persistent().has(&AcademyDataKey::Schedule(schedule_id))
    }
    
    // ============ User Index ============
    
    /// Add schedule ID to user's index
    pub fn add_schedule_to_user_index(env: &Env, user: &Address, schedule_id: u64) {
        let key = AcademyDataKey::UserScheduleIds(user.clone());
        let mut schedule_ids: Vec<u64> = env.storage().persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));
        schedule_ids.push_back(schedule_id);
        env.storage().persistent().set(&key, &schedule_ids);
    }
    
    /// Get all schedule IDs for a user
    pub fn get_user_schedule_ids(env: &Env, user: &Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&AcademyDataKey::UserScheduleIds(user.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }
    
    /// Get schedules for a user (lazy loading)
    pub fn get_user_schedules<T>(env: &Env, user: &Address) -> Vec<T> 
    where
        T: soroban_sdk::TryFromVal<Env, soroban_sdk::Val> + Clone + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    {
        let schedule_ids = Self::get_user_schedule_ids(env, user);
        let mut schedules = Vec::new(env);
        
        for schedule_id in schedule_ids.iter() {
            if let Some(schedule) = Self::get_schedule::<T>(env, schedule_id) {
                schedules.push_back(schedule);
            }
        }
        
        schedules
    }
    
    // ============ Active Schedules Index ============
    
    /// Add schedule to active index
    pub fn add_to_active_index(env: &Env, schedule_id: u64) {
        let mut active: Vec<u64> = env.storage().persistent()
            .get(&AcademyDataKey::ActiveSchedules)
            .unwrap_or_else(|| Vec::new(env));
        active.push_back(schedule_id);
        env.storage().persistent().set(&AcademyDataKey::ActiveSchedules, &active);
    }
    
    /// Remove schedule from active index
    pub fn remove_from_active_index(env: &Env, schedule_id: u64) {
        let active: Vec<u64> = env.storage().persistent()
            .get(&AcademyDataKey::ActiveSchedules)
            .unwrap_or_else(|| Vec::new(env));
        
        let mut new_active = Vec::new(env);
        for id in active.iter() {
            if id != schedule_id {
                new_active.push_back(id);
            }
        }
        
        env.storage().persistent().set(&AcademyDataKey::ActiveSchedules, &new_active);
    }
    
    /// Get all active schedule IDs
    pub fn get_active_schedule_ids(env: &Env) -> Vec<u64> {
        env.storage().persistent()
            .get(&AcademyDataKey::ActiveSchedules)
            .unwrap_or_else(|| Vec::new(env))
    }
    
    // ============ Migration Support ============
    
    /// Check if migration is needed
    pub fn needs_migration(env: &Env) -> bool {
        Self::get_version(env) < CONTRACT_VERSION
    }
    
    /// Perform storage migration
    pub fn migrate_storage(env: &Env) -> u64 {
        let current_version = Self::get_version(env);
        
        if current_version == 0 {
            // First initialization
            Self::set_version(env, CONTRACT_VERSION);
            0
        } else if current_version == 1 {
            // Migrate from v1 to v2
            let migrated = Self::migrate_from_legacy(env);
            Self::set_version(env, CONTRACT_VERSION);
            migrated
        } else {
            0
        }
    }
    
    fn migrate_from_legacy(env: &Env) -> u64 {
        let mut migrated = 0u64;
        
        // Migrate admin
        let legacy_admin_key = symbol_short!("admin");
        if let Some(admin) = env.storage().persistent().get::<_, Address>(&legacy_admin_key) {
            Self::set_admin(env, &admin);
            migrated += 1;
        }
        
        // Migrate token
        let legacy_token_key = symbol_short!("token");
        if let Some(token) = env.storage().persistent().get::<_, Address>(&legacy_token_key) {
            Self::set_token(env, &token);
            migrated += 1;
        }
        
        // Migrate governance
        let legacy_gov_key = symbol_short!("gov");
        if let Some(gov) = env.storage().persistent().get::<_, Address>(&legacy_gov_key) {
            Self::set_governance(env, &gov);
            migrated += 1;
        }
        
        // Migrate counter
        let legacy_counter_key = symbol_short!("cnt");
        if let Some(counter) = env.storage().persistent().get::<_, u64>(&legacy_counter_key) {
            env.storage().instance().set(&AcademyDataKey::Counter, &counter);
            migrated += 1;
        }
        
        migrated
    }
    
    /// Check if legacy data exists
    pub fn has_legacy_data(env: &Env) -> bool {
        env.storage().persistent().has(&symbol_short!("admin")) ||
        env.storage().persistent().has(&symbol_short!("token")) ||
        env.storage().persistent().has(&symbol_short!("gov")) ||
        env.storage().persistent().has(&symbol_short!("cnt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_data_key_variants() {
        // Test that data keys can be created and are distinct
        let key1 = AcademyDataKey::Init;
        let key2 = AcademyDataKey::Counter;
        let key3 = AcademyDataKey::Schedule(1);
        
        // Just verify they compile and are different variants
        match key1 {
            AcademyDataKey::Init => (),
            _ => panic!("Expected Init"),
        }
        
        match key2 {
            AcademyDataKey::Counter => (),
            _ => panic!("Expected Counter"),
        }
        
        match key3 {
            AcademyDataKey::Schedule(id) => assert_eq!(id, 1),
            _ => panic!("Expected Schedule"),
        }
    }
}
