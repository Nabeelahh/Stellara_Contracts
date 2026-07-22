#![cfg(test)]

extern crate std;

use cross_chain_router::CrossChainRouter;
use messaging::UpgradeableMessagingContract;
use shared::circuit_breaker::CircuitBreakerConfig;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Bytes, BytesN, Env, Vec,
};

const BASE_TS: u64 = 1_000;

fn cb_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        max_volume_per_period: 1_000_000_000,
        max_tx_count_per_period: 100,
        period_duration: 3600,
    }
}

fn setup_cross_chain(env: &Env) -> (cross_chain_router::CrossChainRouterClient<'_>, Address) {
    let contract_id = env.register_contract(None, CrossChainRouter);
    let client = cross_chain_router::CrossChainRouterClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.init(&admin);
    (client, admin)
}

fn setup_messaging(env: &Env) -> (messaging::UpgradeableMessagingContractClient<'_>, Address, Address, Address) {
    let contract_id = env.register_contract(None, UpgradeableMessagingContract);
    let client = messaging::UpgradeableMessagingContractClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let approver = Address::generate(env);
    let executor = Address::generate(env);

    let mut approvers = Vec::new(env);
    approvers.push_back(approver.clone());

    env.mock_all_auths();
    client.init(&admin, &approvers, &executor, &cb_config());

    (client, admin, approver, executor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay Attack Rejection Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cross_chain_duplicate_message_rejected() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let payload = Bytes::from_array(&env, &[1u8; 32]);

    let result1 = client.process_message(&0u32, &1u32, &100u64, &payload);
    assert!(result1, "First process should succeed");

    let result2 = client.process_message(&0u32, &1u32, &100u64, &payload);
    assert!(!result2, "Duplicate message should be rejected");
}

#[test]
fn test_cross_chain_same_payload_different_nonces_accepted() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let payload = Bytes::from_array(&env, &[2u8; 32]);

    let result1 = client.process_message(&0u32, &1u32, &100u64, &payload);
    assert!(result1);

    let result2 = client.process_message(&0u32, &1u32, &101u64, &payload);
    assert!(result2);
}

#[test]
fn test_cross_chain_verify_replay_rejected() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let payload = Bytes::from_array(&env, &[3u8; 32]);

    let message_id = client.initiate_message(&0, &1, &sender, &recipient, &payload);

    let proof = Bytes::from_array(&env, &[4u8; 32]);
    let commitment_root = env.crypto().sha256(&proof);

    let header = cross_chain_router::LightClientHeader {
        block_number: 1,
        block_hash: BytesN::from_array(&env, &[5u8; 32]),
        timestamp: BASE_TS,
        commitment_root: commitment_root.into(),
    };
    client.update_light_client(&header);

    let first_verify = client.verify_message(&message_id, &header, &proof);
    assert!(first_verify, "First verify should succeed");

    let replay = client.try_verify_message(&message_id, &header, &proof);
    assert!(replay.is_err(), "Replay should be rejected via verify_message");
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee Enforcement Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_fee_accounting_tracks_fees() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, admin) = setup_cross_chain(&env);

    let accounting_before = client.get_fee_accounting();
    assert_eq!(accounting_before.base_fee, 0);
    assert_eq!(accounting_before.gas_fee, 0);

    client.set_fees(&admin, &500i128, &200i128);

    let accounting_after = client.get_fee_accounting();
    assert_eq!(accounting_after.base_fee, 500);
    assert_eq!(accounting_after.gas_fee, 200);
}

#[test]
fn test_fee_enforcement_on_process_message() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, admin) = setup_cross_chain(&env);

    client.set_fees(&admin, &100i128, &50i128);

    let payload = Bytes::from_array(&env, &[6u8; 32]);
    let result = client.process_message(&0u32, &1u32, &200u64, &payload);
    assert!(result, "Process message with fees should succeed");

    let accounting = client.get_fee_accounting();
    assert_eq!(accounting.base_fee, 100);
    assert_eq!(accounting.gas_fee, 50);
}

#[test]
fn test_zero_fees_allow_processing() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let payload = Bytes::from_array(&env, &[7u8; 32]);
    let result = client.process_message(&0u32, &1u32, &300u64, &payload);
    assert!(result, "Process message with zero fees should succeed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Malformed Payload Handling Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_empty_payload_accepted_by_process_message() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let empty_payload = Bytes::new(&env);
    let result = client.process_message(&0u32, &1u32, &400u64, &empty_payload);
    assert!(result, "Empty payload should be accepted by process_message");
}

#[test]
fn test_large_payload_accepted_by_process_message() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin) = setup_cross_chain(&env);

    let large_payload = Bytes::from_array(&env, &[0xffu8; 1024]);
    let result = client.process_message(&0u32, &1u32, &500u64, &large_payload);
    assert!(result, "Large payload should be accepted by process_message");
}

#[test]
fn test_messaging_rejects_empty_payload() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin, _approver, _executor) = setup_messaging(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let result = client.try_send_message(&alice, &bob, &soroban_sdk::String::from_str(&env, ""));
    assert!(result.is_err(), "Messaging should reject empty payload");
}

#[test]
fn test_messaging_rejects_oversized_payload() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin, _approver, _executor) = setup_messaging(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let oversized = std::string::String::from("a").repeat(1025);
    let result = client.try_send_message(
        &alice,
        &bob,
        &soroban_sdk::String::from_str(&env, &oversized),
    );
    assert!(result.is_err(), "Messaging should reject oversized payload");
}

// ─────────────────────────────────────────────────────────────────────────────
// Messaging Message Hash Computation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_messaging_compute_message_hash_deterministic() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin, _approver, _executor) = setup_messaging(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let hash1 = client.compute_message_hash_public(
        &alice,
        &bob,
        &soroban_sdk::String::from_str(&env, "test"),
        &100u64,
    );
    let hash2 = client.compute_message_hash_public(
        &alice,
        &bob,
        &soroban_sdk::String::from_str(&env, "test"),
        &100u64,
    );
    assert_eq!(hash1, hash2, "Hash should be deterministic for same inputs");
}

#[test]
fn test_messaging_different_nonces_produce_different_hashes() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (client, _admin, _approver, _executor) = setup_messaging(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    let hash1 = client.compute_message_hash_public(
        &alice,
        &bob,
        &soroban_sdk::String::from_str(&env, "test"),
        &100u64,
    );
    let hash2 = client.compute_message_hash_public(
        &alice,
        &bob,
        &soroban_sdk::String::from_str(&env, "test"),
        &101u64,
    );
    assert_ne!(hash1, hash2, "Different nonces should produce different hashes");
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-Contract Interaction: Messaging + Cross-Chain Router
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_messaging_notification_after_cross_chain_process() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (router, _r_admin) = setup_cross_chain(&env);
    let (messaging, _m_admin, _approver, _executor) = setup_messaging(&env);

    let payload = Bytes::from_array(&env, &[8u8; 32]);
    let result = router.process_message(&0u32, &1u32, &600u64, &payload);
    assert!(result, "Cross-chain process should succeed");

    let notifier = Address::generate(&env);
    let user = Address::generate(&env);
    let msg_payload = soroban_sdk::String::from_str(&env, "Cross-chain message received");

    let message_id = messaging.send_message(&notifier, &user, &msg_payload);
    assert_eq!(message_id, 1);

    let unread = messaging.get_unread_count(&user);
    assert_eq!(unread, 1);
}

#[test]
fn test_cross_chain_fee_and_messaging_independent_state() {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = BASE_TS);
    env.mock_all_auths();

    let (router, r_admin) = setup_cross_chain(&env);
    let (messaging, _m_admin, _approver, _executor) = setup_messaging(&env);

    router.set_fees(&r_admin, &100i128, &50i128);

    let accounting = router.get_fee_accounting();
    assert_eq!(accounting.base_fee, 100);
    assert_eq!(accounting.gas_fee, 50);

    let stats = messaging.get_stats();
    assert_eq!(stats.total_messages, 0);

    let router_accounting = router.get_fee_accounting();
    assert_eq!(router_accounting.total_collected, 0);
    assert_eq!(router_accounting.total_distributed, 0);
}
