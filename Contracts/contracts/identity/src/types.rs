use soroban_sdk::{contracttype, Address, BytesN, Vec};

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
    pub did_uri: Vec<u8>,
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
    pub signature: BytesN<64>,  // Optional: Off-chain signature verification
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
