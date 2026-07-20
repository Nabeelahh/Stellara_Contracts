#![cfg(test)]

use super::*;
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

fn create_token(
    env: &Env,
    admin: &Address,
) -> (Address, TokenClient<'static>, StellarAssetClient<'static>) {
    let address = env.register_stellar_asset_contract_v2(admin.clone()).address();
    (
        address.clone(),
        TokenClient::new(env, &address),
        StellarAssetClient::new(env, &address),
    )
}

#[test]
fn test_staking_workflow() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    // Create tokens
    let (staking_token_address, staking_token, staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, reward_token, reward_token_admin) = create_token(&env, &admin);

    // Register contract
    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    // Initialize
    client.initialize(&admin, &staking_token_address, &reward_token_address);

    // Mint tokens to user
    staking_token_admin.mint(&user, &10000);
    reward_token_admin.mint(&contract_id, &100000); // Fund the contract with rewards

    // User stakes 1000 in pool 0 (30 days, 5% APY)
    client.stake(&user, &1000, &0);

    assert_eq!(staking_token.balance(&user), 9000);
    assert_eq!(staking_token.balance(&contract_id), 1000);

    // Jump time: 15 days (1/2 of 30 days)
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 15 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 10,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Check pending rewards
    // 1000 * 0.05 * (15 / 365) = approx 2.05... truncated to 2
    let pending = client.get_pending_rewards(&user);
    assert!(pending > 0);
    assert_eq!(pending, 2);

    // Jump to 31 days (Expired lockup)
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 31 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 20,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Claim rewards
    let claimed = client.claim(&user);
    assert_eq!(claimed, 4); // 1000 * 0.05 * (31 / 365) = 4.24...
    assert_eq!(reward_token.balance(&user), 4);

    // Unstake
    let returned = client.unstake(&user);
    assert_eq!(returned, 1000); // No penalty after 30 days
    assert_eq!(staking_token.balance(&user), 10000);
}

#[test]
fn test_early_withdrawal_penalty() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let (staking_token_address, _staking_token, staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    staking_token_admin.mint(&user, &1000);
    client.stake(&user, &1000, &0); // 30 day pool

    // Jump 1 day (Early)
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 1 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 10,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Unstake early (10% penalty)
    let returned = client.unstake(&user);
    assert_eq!(returned, 900); // 1000 - 100
}

#[test]
fn test_early_unstake_pays_pending_rewards() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let (staking_token_address, staking_token, staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, reward_token, reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    staking_token_admin.mint(&user, &1000);
    reward_token_admin.mint(&contract_id, &100000);

    client.stake(&user, &1000, &0);

    // Jump 15 days — inside the 30-day lockup, but rewards have accrued
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 15 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 10,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    let pending = client.get_pending_rewards(&user);
    assert!(pending > 0, "expected pending rewards before early unstake");

    // Early unstake: 10% penalty on principal, but rewards still paid
    let returned = client.unstake(&user);
    assert_eq!(returned, 900); // 1000 - 10% penalty

    assert_eq!(staking_token.balance(&user), 900);
    assert_eq!(reward_token.balance(&user), pending);
}

#[test]
fn test_compounding() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    // In compounding test, staking token and reward token MUST be the same
    let (token_address, token, token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &token_address, &token_address);

    token_admin.mint(&user, &1000);
    client.stake(&user, &1000, &2); // 90 day pool (15% APY)

    // Jump 180 days (half year)
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 180 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 10,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Pending: 1000 * 0.15 * (180 / 365) = 150 * 0.493... = 73.97 -> 73
    let pending = client.get_pending_rewards(&user);
    assert_eq!(pending, 73);

    // Compound
    client.compound(&user);

    let stake_info = client.get_stake(&user).unwrap();
    assert_eq!(stake_info.amount, 1073);
    assert_eq!(token.balance(&user), 0);
}

#[test]
#[should_panic]
fn test_overflow_protection_in_reward_calculation() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let (staking_token_address, _staking_token, staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    // Stake an amount large enough to overflow in reward calculation.
    // With pool 0 (apy_bps=500) and 1 year elapsed:
    //   amount * 500 * 31_536_000 overflows i128 when amount > ~1.08e28.
    // Use 10^29 to guarantee the second checked_mul returns None.
    let large_amount: i128 = 100_000_000_000_000_000_000_000_000_000_i128;
    staking_token_admin.mint(&user, &large_amount);
    client.stake(&user, &large_amount, &0);

    // Advance one year
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: 365 * 24 * 60 * 60,
        protocol_version: 26,
        sequence_number: 10,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Claiming should panic (ArithmeticOverflow) because the numerator exceeds i128::MAX
    client.claim(&user);
}

#[test]
#[should_panic]
fn test_overflow_protection_on_early_withdrawal_penalty() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let (staking_token_address, _staking_token, staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    // Stake i128::MAX tokens; adding to an empty stake (0 + MAX) does not overflow.
    staking_token_admin.mint(&user, &i128::MAX);
    client.stake(&user, &i128::MAX, &0);

    // Immediately unstake without advancing time → early withdrawal applies.
    // Penalty calc: i128::MAX * 1_000 overflows i128 → should panic (ArithmeticOverflow).
    client.unstake(&user);
}

#[test]
fn test_parameter_proposal_and_execution() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    let (staking_token_address, _staking_token, _staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    // Propose parameter change
    let parameter_key = symbol_short!("p_cfg");
    let new_value = 1000u128;

    let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value);

    // Verify proposal was created
    let proposal = client.get_parameter_proposal(&proposal_id);
    assert_eq!(proposal.parameter_key, parameter_key);
    assert_eq!(proposal.new_value, new_value);
    assert_eq!(proposal.executed, false);
    assert_eq!(proposal.cancelled, false);

    // Try to execute before timelock (should fail)
    let result = client.try_execute_parameter_change(&admin, &proposal_id);
    assert!(result.is_err());

    // Advance time past timelock
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: env.ledger().timestamp() + 86401,
        protocol_version: 26,
        sequence_number: 20,
        network_id: [0u8; 32],
        base_reserve: 10,
        max_entry_ttl: 6_312_000,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
    });

    // Execute parameter change
    client.execute_parameter_change(&admin, &proposal_id);

    // Verify proposal is executed
    let proposal = client.get_parameter_proposal(&proposal_id);
    assert_eq!(proposal.executed, true);
}

#[test]
fn test_parameter_proposal_cancellation() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);

    let (staking_token_address, _staking_token, _staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    // Propose parameter change
    let parameter_key = symbol_short!("p_cfg");
    let new_value = 1000u128;

    let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value);

    // Cancel proposal
    client.cancel_parameter_proposal(&admin, &proposal_id);

    // Verify proposal is cancelled
    let proposal = client.get_parameter_proposal(&proposal_id);
    assert_eq!(proposal.cancelled, true);

    // Try to execute cancelled proposal (should fail)
    let result = client.try_execute_parameter_change(&admin, &proposal_id);
    assert!(result.is_err());
}

#[test]
fn test_parameter_proposal_unauthorized() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    let (staking_token_address, _staking_token, _staking_token_admin) = create_token(&env, &admin);
    let (reward_token_address, _reward_token, _reward_token_admin) = create_token(&env, &admin);

    let contract_id = env.register(StakingRewardsContract, ());
    let client = StakingRewardsContractClient::new(&env, &contract_id);

    client.initialize(&admin, &staking_token_address, &reward_token_address);

    let parameter_key = symbol_short!("p_cfg");
    let new_value = 1000u128;

    // Try to propose parameter change with unauthorized address
    let result = client.try_propose_parameter_change(&unauthorized, &parameter_key, &new_value);
    assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
}