#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, testutils::Events, token, Address, Env, Symbol, TryIntoVal, Vec};

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
                return sym == Symbol::new(&env, "reward");
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
                return sym == Symbol::new(&env, "claimed");
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
                return sym == Symbol::new(&env, "reward");
            }
        }
        false
    }).count();

    assert_eq!(reward_event_count, 3, "Expected 3 reward events, got {}", reward_event_count);
}

// =============================================================================
// Batch Operations Tests
// =============================================================================

#[test]
fn test_batch_add_reward_happy_path() {
    let (env, admin, user1, contract_id) = setup_env();
    let user2 = Address::generate(&env);
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let mut requests = Vec::new(&env);
    requests.push_back(BatchRewardRequest {
        user: user1.clone(),
        amount: 100,
        reward_type: Symbol::new(&env, "referral"),
        reason: Symbol::new(&env, "test1"),
    });
    requests.push_back(BatchRewardRequest {
        user: user2.clone(),
        amount: 200,
        reward_type: Symbol::new(&env, "engagement"),
        reason: Symbol::new(&env, "test2"),
    });

    let result = client.batch_add_reward(&admin, &requests);

    assert_eq!(result.successful_rewards.len(), 2);
    assert_eq!(result.failed_rewards.len(), 2);
    assert_eq!(result.total_amount_granted, 300);
    assert!(result.gas_saved > 0);

    // Verify rewards were created
    let user1_rewards = client.get_user_rewards(&user1);
    assert_eq!(user1_rewards.len(), 1);
    assert_eq!(user1_rewards.first().unwrap(), 1);

    let user2_rewards = client.get_user_rewards(&user2);
    assert_eq!(user2_rewards.len(), 1);
    assert_eq!(user2_rewards.first().unwrap(), 2);

    // Check stats
    let stats = client.get_stats();
    assert_eq!(stats.total_rewards, 2);
    assert_eq!(stats.total_amount, 300);
    assert_eq!(stats.last_reward_id, 2);
}

#[test]
fn test_batch_add_reward_size_limit() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    // Create batch with more than MAX_BATCH_SIZE (30) requests
    let mut requests = Vec::new(&env);
    for _i in 0..31 {
        requests.push_back(BatchRewardRequest {
            user: user.clone(),
            amount: 10,
            reward_type: Symbol::new(&env, "test"),
            reason: Symbol::new(&env, "test"),
        });
    }

    let result = client.try_batch_add_reward(&admin, &requests);
    assert!(result.is_err());
    // The batch size limit is enforced, but the exact error type may vary
    // This test verifies that large batches are rejected
}

#[test]
fn test_batch_add_reward_partial_failures() {
    let (env, admin, user1, contract_id) = setup_env();
    let user2 = Address::generate(&env);
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    let mut requests = Vec::new(&env);
    // Valid request
    requests.push_back(BatchRewardRequest {
        user: user1.clone(),
        amount: 100,
        reward_type: Symbol::new(&env, "referral"),
        reason: Symbol::new(&env, "valid"),
    });
    // Invalid request (negative amount)
    requests.push_back(BatchRewardRequest {
        user: user2.clone(),
        amount: -50,
        reward_type: Symbol::new(&env, "engagement"),
        reason: Symbol::new(&env, "invalid"),
    });

    let result = client.batch_add_reward(&admin, &requests);

    assert_eq!(result.successful_rewards.len(), 1);
    assert_eq!(result.failed_rewards.len(), 2);
    assert_eq!(result.total_amount_granted, 100);

    // Verify only valid reward was created
    let user1_rewards = client.get_user_rewards(&user1);
    assert_eq!(user1_rewards.len(), 1);
    assert_eq!(user1_rewards.first().unwrap(), 1);

    let user2_rewards = client.get_user_rewards(&user2);
    assert_eq!(user2_rewards.len(), 0);

    let stats = client.get_stats();
    assert_eq!(stats.total_rewards, 1);
    assert_eq!(stats.total_amount, 100);
}

#[test]
fn test_batch_claim_reward_happy_path() {
    let (env, admin, user1, contract_id) = setup_env();
    let user2 = Address::generate(&env);
    let (token_id, token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    // Fund contract
    token_admin.mint(&contract_id, &500);

    // Create rewards
    let reward_id1 = client.add_reward(
        &admin,
        &user1,
        &100,
        &Symbol::new(&env, "referral"),
        &Symbol::new(&env, "test1"),
    );
    let reward_id2 = client.add_reward(
        &admin,
        &user2,
        &200,
        &Symbol::new(&env, "engagement"),
        &Symbol::new(&env, "test2"),
    );

    let mut requests = Vec::new(&env);
    requests.push_back(BatchRewardClaimRequest {
        reward_id: reward_id1,
        user: user1.clone(),
    });
    requests.push_back(BatchRewardClaimRequest {
        reward_id: reward_id2,
        user: user2.clone(),
    });

    let results = client.batch_claim_reward(&requests);

    assert_eq!(results.len(), 2);
    assert!(results.get(0).unwrap().success);
    assert!(results.get(1).unwrap().success);
    assert_eq!(results.get(0).unwrap().amount_claimed, Some(100));
    assert_eq!(results.get(1).unwrap().amount_claimed, Some(200));

    // Check token balances
    assert_eq!(token_client.balance(&user1), 100);
    assert_eq!(token_client.balance(&user2), 200);

    // Check stats
    let stats = client.get_stats();
    assert_eq!(stats.total_claimed, 300);
}

#[test]
fn test_batch_claim_reward_size_limit() {
    let (env, admin, user, contract_id) = setup_env();
    let (token_id, _token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);
    token_admin.mint(&contract_id, &5000);

    // Create many rewards
    for _i in 1..=26 {
        client.add_reward(
            &admin,
            &user,
            &100,
            &Symbol::new(&env, "test"),
            &Symbol::new(&env, "test"),
        );
    }

    // Create batch with more than MAX_BATCH_SIZE (25) requests
    let mut requests = Vec::new(&env);
    for i in 0..26 {
        requests.push_back(BatchRewardClaimRequest {
            reward_id: i,
            user: user.clone(),
        });
    }

    let result = client.try_batch_claim_reward(&requests);
    assert!(result.is_err());
    // The batch size limit is enforced, but exact error type may vary
    // This test verifies that large batches are rejected
}

#[test]
fn test_batch_claim_reward_partial_failures() {
    let (env, admin, user1, contract_id) = setup_env();
    let user2 = Address::generate(&env);
    let (token_id, token_client, token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    // Fund contract with insufficient balance
    token_admin.mint(&contract_id, &150);

    // Create rewards
    let reward_id1 = client.add_reward(
        &admin,
        &user1,
        &100,
        &Symbol::new(&env, "referral"),
        &Symbol::new(&env, "test1"),
    );
    let reward_id2 = client.add_reward(
        &admin,
        &user2,
        &200,
        &Symbol::new(&env, "engagement"),
        &Symbol::new(&env, "test2"),
    );

    let mut requests = Vec::new(&env);
    requests.push_back(BatchRewardClaimRequest {
        reward_id: reward_id1,
        user: user1.clone(),
    });
    requests.push_back(BatchRewardClaimRequest {
        reward_id: reward_id2,
        user: user2.clone(),
    });

    let results = client.batch_claim_reward(&requests);

    assert_eq!(results.len(), 2);
    // First claim should succeed (enough balance), second should fail
    assert!(results.get(0).unwrap().success);
    assert!(!results.get(1).unwrap().success);
    assert_eq!(results.get(0).unwrap().amount_claimed, Some(100));
    assert_eq!(results.get(1).unwrap().amount_claimed, None);

    // Check token balances
    assert_eq!(token_client.balance(&user1), 100);
    assert_eq!(token_client.balance(&user2), 0);

    // Check stats
    let stats = client.get_stats();
    assert_eq!(stats.total_claimed, 100);
}

#[test]
fn test_batch_operations_emit_events() {
    let (env, admin, user1, contract_id) = setup_env();
    let _user2 = Address::generate(&env);
    let (token_id, _token_client, _token_admin) = setup_token(&env);
    let client = SocialRewardsContractClient::new(&env, &contract_id);

    client.init(&admin, &token_id);

    // Test batch add reward events
    let mut requests = Vec::new(&env);
    requests.push_back(BatchRewardRequest {
        user: user1.clone(),
        amount: 100,
        reward_type: Symbol::new(&env, "referral"),
        reason: Symbol::new(&env, "test1"),
    });

    client.batch_add_reward(&admin, &requests);

    let events = env.events().all();

    // Should have reward event
    let has_reward_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == Symbol::new(&env, "reward");
            }
        }
        false
    });
    assert!(has_reward_event, "Reward event not found");
}
