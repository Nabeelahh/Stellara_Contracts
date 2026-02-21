use soroban_sdk::{Env, Address, BytesN};
use crate::types::{DataKey, IdentityMetadata, Credential};

pub fn get_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Admin)
}

pub fn set_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

pub fn has_admin(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Admin)
}

pub fn get_identity(env: &Env, address: &Address) -> Option<IdentityMetadata> {
    env.storage().persistent().get(&DataKey::Identity(address.clone()))
}

pub fn set_identity(env: &Env, address: &Address, metadata: &IdentityMetadata) {
    env.storage().persistent().set(&DataKey::Identity(address.clone()), metadata);
}

pub fn get_credential(env: &Env, claim_hash: &BytesN<32>) -> Option<Credential> {
    env.storage().persistent().get(&DataKey::Credential(claim_hash.clone()))
}

pub fn set_credential(env: &Env, claim_hash: &BytesN<32>, credential: &Credential) {
    env.storage().persistent().set(&DataKey::Credential(claim_hash.clone()), credential);
}

pub fn is_verifier(env: &Env, address: &Address) -> bool {
    env.storage().instance().get(&DataKey::Verifier(address.clone())).unwrap_or(false)
}

pub fn set_verifier(env: &Env, address: &Address, status: bool) {
    env.storage().instance().set(&DataKey::Verifier(address.clone()), &status);
}
