#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Env, BytesN, Bytes};
use crate::types::CredentialType;

#[test]
fn test_identity_registration() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, IdentityContract);
    let client = IdentityContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let user = Address::generate(&env);
    let did_uri = Bytes::from_slice(&env, b"did:stellara:123");
    let public_key = BytesN::from_array(&env, &[1u8; 32]);

    client.register_identity(&user, &did_uri, &public_key);

    let id = client.get_id(&user).unwrap();
    assert_eq!(id.did_uri, did_uri);
    assert_eq!(id.public_key, public_key);
}

#[test]
fn test_credential_issuance_and_verification() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, IdentityContract);
    let client = IdentityContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let issuer = Address::generate(&env);
    client.add_verifier(&issuer);

    let subject = Address::generate(&env);
    let data = Bytes::from_slice(&env, b"Graduated from Stellara Academy");
    let salt = BytesN::from_array(&env, &[9u8; 32]);
    
    // Pre-calculate hash
    let mut bytes = Bytes::new(&env);
    bytes.append(&data);
    bytes.append(&salt.clone().into());
    let claim_hash = env.crypto().sha256(&bytes);

    client.issue_credential(&issuer, &subject, &CredentialType::AcademyGraduation, &claim_hash, &None);

    let cred = client.get_cred(&claim_hash).unwrap();
    assert_eq!(cred.subject, subject);
    assert_eq!(cred.issuer, issuer);

    // Verify
    let is_valid = client.verify_credential(&claim_hash, &data, &salt);
    assert!(is_valid);
}

#[test]
fn test_unauthorized_issuer() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, IdentityContract);
    let client = IdentityContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);

    let unauthorized = Address::generate(&env);
    let subject = Address::generate(&env);
    let claim_hash = BytesN::from_array(&env, &[0u8; 32]);

    let res = client.try_issue_credential(&unauthorized, &subject, &CredentialType::AcademyGraduation, &claim_hash, &None);
    
    assert!(res.is_err());
}
