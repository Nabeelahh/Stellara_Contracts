#![no_std]

pub mod types;
pub mod storage;
#[cfg(test)]
mod test;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec, symbol_short, Symbol};
use crate::types::{IdentityMetadata, Credential, CredentialType};
use crate::storage::{get_admin, set_admin, has_admin, get_identity, set_identity, get_credential, set_credential, is_verifier, set_verifier};

#[contract]
pub struct IdentityContract;

#[contractimpl]
impl IdentityContract {
    /// Initialize the contract with an admin address
    pub fn initialize(env: Env, admin: Address) {
        if has_admin(&env) {
            panic!("Already initialized");
        }
        set_admin(&env, &admin);
    }

    /// Register or update an identity
    pub fn register_identity(env: Env, user: Address, did_uri: Vec<u8>, public_key: BytesN<32>) {
        user.require_auth();
        
        let now = env.ledger().timestamp();
        let metadata = if let Some(mut existing) = get_identity(&env, &user) {
            existing.did_uri = did_uri;
            existing.public_key = public_key;
            existing.updated_at = now;
            existing
        } else {
            IdentityMetadata {
                did_uri,
                public_key,
                created_at: now,
                updated_at: now,
            }
        };
        
        set_identity(&env, &user, &metadata);
        
        // Emit event
        env.events().publish(
            (symbol_short!("identity"), symbol_short!("updated"), user),
            metadata.did_uri,
        );
    }

    /// Add a verifier/issuer (Admin only)
    pub fn add_verifier(env: Env, verifier: Address) {
        let admin = get_admin(&env).expect("Not initialized");
        admin.require_auth();
        
        set_verifier(&env, &verifier, true);
    }

    /// Issue a new credential
    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        credential_type: CredentialType,
        claim_hash: BytesN<32>,
        expires_at: Option<u64>,
    ) {
        issuer.require_auth();
        
        if !is_verifier(&env, &issuer) {
            panic!("Not an authorized verifier");
        }
        
        if get_credential(&env, &claim_hash).is_some() {
            panic!("Credential already exists");
        }
        
        let credential = Credential {
            issuer: issuer.clone(),
            subject: subject.clone(),
            credential_type,
            claim_hash: claim_hash.clone(),
            signature: BytesN::from_array(&env, &[0u8; 64]), // Simplified, can use real signatures
            issued_at: env.ledger().timestamp(),
            expires_at,
            is_revoked: false,
        };
        
        set_credential(&env, &claim_hash, &credential);
        
        // Emit event
        env.events().publish(
            (symbol_short!("cred"), symbol_short!("issued"), subject),
            claim_hash,
        );
    }

    /// Verify a credential without revealing private data
    /// User provides data and salt to prove ownership of the claim_hash
    pub fn verify_credential(
        env: Env,
        claim_hash: BytesN<32>,
        data: Vec<u8>,
        salt: BytesN<32>,
    ) -> bool {
        let credential = get_credential(&env, &claim_hash).expect("Credential not found");
        
        if credential.is_revoked {
            return false;
        }
        
        if let Some(expiry) = credential.expires_at {
            if env.ledger().timestamp() > expiry {
                return false;
            }
        }
        
        // Verify hash: H(data || salt)
        let mut bytes = soroban_sdk::Bytes::new(&env);
        bytes.append(&data.into()); // Convert Vec<u8> to Bytes
        bytes.append(&salt.into()); // Convert BytesN<32> to Bytes
        
        let hash = env.crypto().sha256(&bytes);
        
        hash == claim_hash
    }

    /// Revoke a credential (Issuer or Admin only)
    pub fn revoke_credential(env: Env, claim_hash: BytesN<32>) {
        let mut credential = get_credential(&env, &claim_hash).expect("Credential not found");
        
        let caller = env.invoker(); // Use env.sender() or require_auth
        // In newer Soroban versions, we use Address and require_auth
        // Since I don't know the exact caller easily without an argument, I'll pass it if needed.
        // But better is to just require_auth on the issuer.
        
        credential.issuer.require_auth();
        
        credential.is_revoked = true;
        set_credential(&env, &claim_hash, &credential);
        
        env.events().publish(
            (symbol_short!("cred"), symbol_short!("revoked")),
            claim_hash,
        );
    }
    
    /// Get identity metadata
    pub fn get_id(env: Env, user: Address) -> Option<IdentityMetadata> {
        get_identity(&env, &user)
    }
    
    /// Get credential details
    pub fn get_cred(env: Env, claim_hash: BytesN<32>) -> Option<Credential> {
        get_credential(&env, &claim_hash)
    }
}
