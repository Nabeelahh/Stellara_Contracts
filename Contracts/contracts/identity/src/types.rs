use soroban_sdk::{contracttype, Address, BytesN, Bytes};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialType {
    AcademyGraduation,
    CourseCertificate,
    SkillBadge,
    IdentityVerification,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityMetadata {
    pub did_uri: Bytes,
    pub public_key: BytesN<32>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub issuer: Address,
    pub subject: Address,
    pub credential_type: CredentialType,
    pub claim_hash: BytesN<32>, // Privacy-preserving: H(data + salt)
    pub signature: Bytes,      // Optional: Off-chain signature verification
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub is_revoked: bool,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Identity(Address),
    Credential(BytesN<32>), // Keyed by claim_hash
    Verifier(Address),      // Authorized issuers/verifiers
}

#[soroban_sdk::contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    NotFound = 4,
    AlreadyExists = 5,
    Revoked = 6,
    Expired = 7,
    InvalidHash = 8,
}
