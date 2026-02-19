#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, testutils::Events, token, Address, Env, Symbol, TryIntoVal};

fn setup_env() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    set_timestamp(&env, 1000);

    let contract_id = env.register_contract(None, SocialRewardsContract);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    (env, admin, user, contract_id)
}

fn setup_token(env: &Env) -> (Address, token::Client<'_>, token::StellarAssetClient<'_>) {
    let issuer = Address::generate(env);
    let token_id = env.register_stellar_asset_contract(issuer);
    let token_client = token::Client::new(env, &token_id);
    let token_admin = token::StellarAssetClient::new(env, &token_id);
    (token_id, token_client, token_admin)
}

fn set_timestamp(env: &Env, timestamp: u64) {
    let mut ledger_info = env.ledger().get();
    ledger_info.timestamp = timestamp;
    env.ledger().set(ledger_info);
}

// =============================================================================
// Basic Functionality Tests
// =============================================================================

#[test]
fn test_init_and_get_info() {
    let (env, admin, _user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let (stored_admin, stored_token) = client.get_info();
    assert_eq!(stored_admin, admin);
    assert_eq!(stored_token, token_id);
}

#[test]
fn test_init_twice_fails() {
    let (env, admin, _user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);
    let result = client.try_init(&admin, &token_id);
    assert_eq!(result, Err(Ok(RewardError::Unauthorized)));
}

#[test]
fn test_add_reward_happy_path() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);
    assert_eq!(reward_id, 1);

    let reward = client.get_reward(&reward_id);
    assert_eq!(reward.user, user);
    assert_eq!(reward.amount, 100);
    assert_eq!(reward.reward_type, reward_type);
    assert!(!reward.claimed);
}

#[test]
fn test_add_reward_invalid_amount_fails() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    // Negative amount - call contract directly to get actual error
    let result = env.as_contract(&contract_id, || {
        SocialRewardsContract::add_reward(env.clone(), admin.clone(), user.clone(), -1, reward_type.clone(), reason.clone())
    });
    assert_eq!(result, Err(RewardError::InvalidAmount));

    // Zero amount
    let result = env.as_contract(&contract_id, || {
        SocialRewardsContract::add_reward(env.clone(), admin.clone(), user.clone(), 0, reward_type.clone(), reason.clone())
    });
    assert_eq!(result, Err(RewardError::InvalidAmount));
}

#[test]
fn test_add_reward_non_admin_fails() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);
    let non_admin = Address::generate(&env);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    let result = client.try_add_reward(&non_admin, &user, &100, &reward_type, &reason);
    assert_eq!(result, Err(Ok(RewardError::Unauthorized)));
}

#[test]
fn test_claim_reward_success() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);

    // Fund contract
    token_admin.mint(&contract_id, &100);

    // Claim reward
    let claimed_amount = client.claim_reward(&reward_id, &user);
    assert_eq!(claimed_amount, 100);

    // Verify token transfer
    assert_eq!(token_client.balance(&user), 100);
    assert_eq!(token_client.balance(&contract_id), 0);

    // Verify reward is marked as claimed
    let reward = client.get_reward(&reward_id);
    assert!(reward.claimed);
}

#[test]
fn test_claim_reward_already_claimed_fails() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);
    token_admin.mint(&contract_id, &100);

    client.claim_reward(&reward_id, &user);

    // Call contract directly to get actual error
    let result = env.as_contract(&contract_id, || {
        SocialRewardsContract::claim_reward(env.clone(), reward_id, user.clone())
    });
    assert_eq!(result, Err(RewardError::AlreadyClaimed));
}

#[test]
fn test_claim_reward_wrong_user_fails() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);
    let other_user = Address::generate(&env);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);
    token_admin.mint(&contract_id, &100);

    let result = client.try_claim_reward(&reward_id, &other_user);
    assert_eq!(result, Err(Ok(RewardError::Unauthorized)));
}

#[test]
fn test_claim_reward_insufficient_balance_fails() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);
    // Don't fund the contract

    // Call contract directly to get actual error
    let result = env.as_contract(&contract_id, || {
        SocialRewardsContract::claim_reward(env.clone(), reward_id, user.clone())
    });
    assert_eq!(result, Err(RewardError::InsufficientBalance));
}

#[test]
fn test_get_user_rewards() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    client.add_reward(&admin, &user, &100, &reward_type, &reason);
    client.add_reward(&admin, &user, &200, &reward_type, &reason);
    client.add_reward(&admin, &user, &300, &reward_type, &reason);

    let user_rewards = client.get_user_rewards(&user);
    assert_eq!(user_rewards.len(), 3);
    assert_eq!(user_rewards.get(0).unwrap(), 1);
    assert_eq!(user_rewards.get(1).unwrap(), 2);
    assert_eq!(user_rewards.get(2).unwrap(), 3);
}

#[test]
fn test_get_stats() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    client.add_reward(&admin, &user, &100, &reward_type, &reason);
    client.add_reward(&admin, &user, &200, &reward_type, &reason);

    let stats = client.get_stats();
    assert_eq!(stats.total_rewards, 2);
    assert_eq!(stats.total_amount, 300);
    assert_eq!(stats.total_claimed, 0);
    assert_eq!(stats.last_reward_id, 2);

    // Claim one reward
    token_admin.mint(&contract_id, &100);
    client.claim_reward(&1, &user);

    let stats = client.get_stats();
    assert_eq!(stats.total_claimed, 100);
}

#[test]
fn test_get_pending_rewards() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    client.add_reward(&admin, &user, &100, &reward_type, &reason);
    client.add_reward(&admin, &user, &200, &reward_type, &reason);

    let pending = client.get_pending_rewards(&user);
    assert_eq!(pending, 300);

    // Claim one reward
    token_admin.mint(&contract_id, &100);
    client.claim_reward(&1, &user);

    let pending = client.get_pending_rewards(&user);
    assert_eq!(pending, 200);
}

// =============================================================================
// Event Emission Tests
// =============================================================================

#[test]
fn test_add_reward_emits_event() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let _reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);

    let events = env.events().all();

    // Check for reward event
    let has_reward_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("reward");
            }
        }
        false
    });
    assert!(has_reward_event, "Reward added event not found");
}

#[test]
fn test_claim_reward_emits_event() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "friend_signup");

    let reward_id = client.add_reward(&admin, &user, &100, &reward_type, &reason);
    token_admin.mint(&contract_id, &100);

    client.claim_reward(&reward_id, &user);

    let events = env.events().all();

    // Check for claimed event
    let has_claimed_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("claimed");
            }
        }
        false
    });
    assert!(has_claimed_event, "Reward claimed event not found");
}

#[test]
fn test_multiple_rewards_emit_multiple_events() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let reward_type = Symbol::new(&env, "referral");
    let reason = Symbol::new(&env, "test");

    client.add_reward(&admin, &user, &100, &reward_type, &reason);
    client.add_reward(&admin, &user, &200, &reward_type, &reason);
    client.add_reward(&admin, &user, &300, &reward_type, &reason);

    let events = env.events().all();

    // Count reward events
    let reward_event_count = events.iter().filter(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("reward");
            }
        }
        false
    }).count();

    assert_eq!(reward_event_count, 3, "Expected 3 reward events, got {}", reward_event_count);
}
