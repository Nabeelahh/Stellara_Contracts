#![cfg(test)]

extern crate std;

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, testutils::Events, token, Address, Env, Symbol, Vec, TryIntoVal};
use shared::governance::ProposalStatus;
use shared::fees::FeeError;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().expect("test lock poisoned")
}

fn setup_env() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    set_timestamp(&env, 1000);

    let contract_id = env.register_contract(None, UpgradeableTradingContract);

    let admin = Address::generate(&env);
    let approver = Address::generate(&env);
    let executor = Address::generate(&env);

    (env, admin, approver, executor, contract_id)
}

fn init_contract(client: &UpgradeableTradingContractClient, admin: &Address, approvers: Vec<Address>, executor: &Address) {
    client.init(admin, &approvers, executor);
}

fn setup_fee_token(env: &Env) -> (Address, token::Client<'_>, token::StellarAssetClient<'_>) {
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

#[test]
fn test_init_and_getters() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);

    init_contract(&client, &admin, approvers, &executor);

    let version = client.get_version();
    let stats = client.get_stats();

    assert_eq!(version, 1);
    assert_eq!(stats.total_trades, 0);
    assert_eq!(stats.total_volume, 0);
    assert_eq!(stats.last_trade_id, 0);
}

#[test]
fn test_init_twice_fails() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);

    init_contract(&client, &admin, approvers.clone(), &executor);

    let result = client.try_init(&admin, &approvers, &executor);
    assert_eq!(result, Err(Ok(TradeError::Unauthorized)));
}

#[test]
fn test_trade_happy_path_updates_stats_and_transfers_fee() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    token_admin.mint(&trader, &1000);

    let trade_id = client.trade(
        &trader,
        &Symbol::new(&env, "XLMUSDC"),
        &250,
        &10,
        &true,
        &token_id,
        &100,
        &fee_recipient,
    );

    assert_eq!(trade_id, 1);
    assert_eq!(token_client.balance(&trader), 900);
    assert_eq!(token_client.balance(&fee_recipient), 100);

    let stats = client.get_stats();
    assert_eq!(stats.total_trades, 1);
    assert_eq!(stats.total_volume, 250);
    assert_eq!(stats.last_trade_id, 1);
}

#[test]
fn test_trade_invalid_fee_amount_fails() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);
    token_admin.mint(&trader, &1000);

    let result = client.try_trade(
        &trader,
        &Symbol::new(&env, "XLMUSDC"),
        &100,
        &10,
        &true,
        &token_id,
        &-1,
        &fee_recipient,
    );

    assert_eq!(result, Err(Ok(FeeError::InvalidAmount)));
}

#[test]
fn test_trade_insufficient_balance_fails() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);
    token_admin.mint(&trader, &50);

    let result = client.try_trade(
        &trader,
        &Symbol::new(&env, "XLMUSDC"),
        &100,
        &10,
        &true,
        &token_id,
        &100,
        &fee_recipient,
    );

    assert_eq!(result, Err(Ok(FeeError::InsufficientBalance)));
}

#[test]
fn test_pause_sets_flag() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    client.pause(&admin);
    let paused = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&symbol_short!("pause")).unwrap_or(false)
    });
    assert!(paused);

    client.unpause(&admin);
    let paused = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&symbol_short!("pause")).unwrap_or(false)
    });
    assert!(!paused);
}

#[test]
fn test_pause_unpause_authorization() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let non_admin = Address::generate(&env);
    let result = client.try_pause(&non_admin);
    assert_eq!(result, Err(Ok(TradeError::Unauthorized)));

    client.pause(&admin);
    let result = client.try_unpause(&non_admin);
    assert_eq!(result, Err(Ok(TradeError::Unauthorized)));

    client.unpause(&admin);
}

#[test]
fn test_upgrade_proposal_flow_and_errors() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    // Invalid threshold -> mapped to Unauthorized
    let invalid = client.try_propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &0,
        &3600,
    );
    assert_eq!(invalid, Err(Ok(TradeError::Unauthorized)));

    // Valid proposal
    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    let proposal = client.get_upgrade_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Pending);

    client.approve_upgrade(&proposal_id, &approver);
    let duplicate = client.try_approve_upgrade(&proposal_id, &approver);
    assert_eq!(duplicate, Err(Ok(TradeError::Unauthorized)));
    let proposal = client.get_upgrade_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Approved);

    // Execute too early
    let execute_err = client.try_execute_upgrade(&proposal_id, &executor);
    assert_eq!(execute_err, Err(Ok(TradeError::Unauthorized)));

    set_timestamp(&env, 1000 + 3601);
    client.execute_upgrade(&proposal_id, &executor);

    let proposal = client.get_upgrade_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Executed);

    // Cancelling executed proposal should fail
    let cancel_err = client.try_cancel_upgrade(&proposal_id, &admin);
    assert_eq!(cancel_err, Err(Ok(TradeError::Unauthorized)));
}

#[test]
fn test_reject_and_get_proposal_errors() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    client.reject_upgrade(&proposal_id, &approver);
    let proposal = client.get_upgrade_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Rejected);

    let missing = client.try_get_upgrade_proposal(&999);
    assert_eq!(missing, Err(Ok(TradeError::Unauthorized)));
}

// =============================================================================
// Event Emission Tests
// =============================================================================

#[test]
fn test_trade_emits_events() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);
    let pair = Symbol::new(&env, "XLMUSDC");

    token_admin.mint(&trader, &1000);

    let trade_id = client.trade(
        &trader,
        &pair,
        &250,
        &10,
        &true,
        &token_id,
        &100,
        &fee_recipient,
    );

    assert_eq!(trade_id, 1);

    // Verify events were emitted
    let events = env.events().all();

    // Should have at least 2 events: fee_collected and trade_executed
    // (plus any token transfer events)
    assert!(events.len() >= 2, "Expected at least 2 events, got {}", events.len());

    // Check for trade event topic
    let has_trade_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("trade");
            }
        }
        false
    });
    assert!(has_trade_event, "Trade event not found");

    // Check for fee event topic
    let has_fee_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("fee");
            }
        }
        false
    });
    assert!(has_fee_event, "Fee event not found");
}

#[test]
fn test_pause_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    client.pause(&admin);

    let events = env.events().all();

    // Check for paused event
    let has_pause_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("paused");
            }
        }
        false
    });
    assert!(has_pause_event, "Pause event not found");
}

#[test]
fn test_unpause_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    client.pause(&admin);
    client.unpause(&admin);

    let events = env.events().all();

    // Check for unpause event
    let has_unpause_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("unpause");
            }
        }
        false
    });
    assert!(has_unpause_event, "Unpause event not found");
}

#[test]
fn test_governance_proposal_emits_events() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    // Create proposal
    let _proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    let events = env.events().all();

    // Check for proposal created event
    let has_propose_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("propose");
            }
        }
        false
    });
    assert!(has_propose_event, "Proposal created event not found");
}

#[test]
fn test_governance_approval_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    client.approve_upgrade(&proposal_id, &approver);

    let events = env.events().all();

    // Check for approval event
    let has_approve_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("approve");
            }
        }
        false
    });
    assert!(has_approve_event, "Approval event not found");
}

#[test]
fn test_governance_execution_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    client.approve_upgrade(&proposal_id, &approver);
    set_timestamp(&env, 1000 + 3601);
    client.execute_upgrade(&proposal_id, &executor);

    let events = env.events().all();

    // Check for execute event
    let has_execute_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("execute");
            }
        }
        false
    });
    assert!(has_execute_event, "Execute event not found");
}

#[test]
fn test_governance_rejection_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    client.reject_upgrade(&proposal_id, &approver);

    let events = env.events().all();

    // Check for reject event
    let has_reject_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("reject");
            }
        }
        false
    });
    assert!(has_reject_event, "Reject event not found");
}

#[test]
fn test_governance_cancellation_emits_event() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver.clone());
    init_contract(&client, &admin, approvers.clone(), &executor);

    let proposal_id = client.propose_upgrade(
        &admin,
        &symbol_short!("v2hash"),
        &symbol_short!("Upgrade"),
        &approvers,
        &1,
        &3600,
    );

    client.cancel_upgrade(&proposal_id, &admin);

    let events = env.events().all();

    // Check for cancel event
    let has_cancel_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("cancel");
            }
        }
        false
    });
    assert!(has_cancel_event, "Cancel event not found");
}

// =============================================================================
// Batch Operations Tests
// =============================================================================

#[test]
fn test_batch_trade_happy_path() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, token_client, token_admin) = setup_fee_token(&env);
    let trader1 = Address::generate(&env);
    let trader2 = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    // Mint tokens for traders
    token_admin.mint(&trader1, &1000);
    token_admin.mint(&trader2, &1000);

    // Create batch requests
    let mut requests = Vec::new(&env);
    requests.push_back(BatchTradeRequest {
        trader: trader1.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 250,
        price: 10,
        is_buy: true,
        fee_token: token_id.clone(),
        fee_amount: 100,
        fee_recipient: fee_recipient.clone(),
    });
    requests.push_back(BatchTradeRequest {
        trader: trader2.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 150,
        price: 12,
        is_buy: false,
        fee_token: token_id.clone(),
        fee_amount: 50,
        fee_recipient: fee_recipient.clone(),
    });

    let result = client.batch_trade(&requests);

    assert_eq!(result.successful_trades.len(), 2);
    assert_eq!(result.failed_trades.len(), 2); // All results are stored in failed_trades
    assert_eq!(result.total_fees_collected, 150);
    assert!(result.gas_saved > 0);

    // Check token balances
    assert_eq!(token_client.balance(&trader1), 900);
    assert_eq!(token_client.balance(&trader2), 950);
    assert_eq!(token_client.balance(&fee_recipient), 150);

    // Check stats
    let stats = client.get_stats();
    assert_eq!(stats.total_trades, 2);
    assert_eq!(stats.total_volume, 400);
    assert_eq!(stats.last_trade_id, 2);
}

#[test]
fn test_batch_trade_size_limit() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    token_admin.mint(&trader, &50000); // Enough for many trades

    // Create batch with more than MAX_BATCH_SIZE (50) requests
    let mut requests = Vec::new(&env);
    for _ in 0..51 {
        requests.push_back(BatchTradeRequest {
            trader: trader.clone(),
            pair: Symbol::new(&env, "XLMUSDC"),
            amount: 10,
            price: 10,
            is_buy: true,
            fee_token: token_id.clone(),
            fee_amount: 1,
            fee_recipient: fee_recipient.clone(),
        });
    }

    let result = client.try_batch_trade(&requests);
    assert_eq!(result, Err(Ok(TradeError::BatchSizeExceeded)));
}

#[test]
fn test_batch_trade_partial_failures() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, token_client, token_admin) = setup_fee_token(&env);
    let trader1 = Address::generate(&env);
    let trader2 = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    // Only mint tokens for trader1
    token_admin.mint(&trader1, &1000);

    let mut requests = Vec::new(&env);
    // Valid trade
    requests.push_back(BatchTradeRequest {
        trader: trader1.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 250,
        price: 10,
        is_buy: true,
        fee_token: token_id.clone(),
        fee_amount: 100,
        fee_recipient: fee_recipient.clone(),
    });
    // Invalid trade (insufficient balance)
    requests.push_back(BatchTradeRequest {
        trader: trader2.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 150,
        price: 12,
        is_buy: false,
        fee_token: token_id.clone(),
        fee_amount: 50,
        fee_recipient: fee_recipient.clone(),
    });

    let result = client.batch_trade(&requests);

    assert_eq!(result.successful_trades.len(), 1);
    assert_eq!(result.failed_trades.len(), 2);
    assert_eq!(result.total_fees_collected, 100);

    // Check that only the successful trade was processed
    assert_eq!(token_client.balance(&trader1), 900);
    assert_eq!(token_client.balance(&trader2), 0);
    assert_eq!(token_client.balance(&fee_recipient), 100);

    let stats = client.get_stats();
    assert_eq!(stats.total_trades, 1);
    assert_eq!(stats.total_volume, 250);
}

#[test]
fn test_batch_trade_when_paused() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    token_admin.mint(&trader, &1000);

    // Pause contract
    client.pause(&admin);

    let mut requests = Vec::new(&env);
    requests.push_back(BatchTradeRequest {
        trader: trader.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 250,
        price: 10,
        is_buy: true,
        fee_token: token_id.clone(),
        fee_amount: 100,
        fee_recipient: fee_recipient.clone(),
    });

    let result = client.try_batch_trade(&requests);
    assert_eq!(result, Err(Ok(TradeError::ContractPaused)));
}

#[test]
fn test_batch_trade_emits_events() {
    let _guard = serial_lock();
    let (env, admin, approver, executor, contract_id) = setup_env();
    let client = UpgradeableTradingContractClient::new(&env, &contract_id);
    let mut approvers = Vec::new(&env);
    approvers.push_back(approver);
    init_contract(&client, &admin, approvers, &executor);

    let (token_id, _token_client, token_admin) = setup_fee_token(&env);
    let trader = Address::generate(&env);
    let fee_recipient = Address::generate(&env);

    token_admin.mint(&trader, &1000);

    let mut requests = Vec::new(&env);
    requests.push_back(BatchTradeRequest {
        trader: trader.clone(),
        pair: Symbol::new(&env, "XLMUSDC"),
        amount: 250,
        price: 10,
        is_buy: true,
        fee_token: token_id,
        fee_amount: 100,
        fee_recipient: fee_recipient.clone(),
    });

    client.batch_trade(&requests);

    let events = env.events().all();

    // Should have fee and trade events
    let has_trade_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("trade");
            }
        }
        false
    });
    assert!(has_trade_event, "Trade event not found");

    let has_fee_event = events.iter().any(|(_, topics, _)| {
        if let Some(first_topic) = topics.first() {
            let topic_str: Result<Symbol, _> = first_topic.clone().try_into_val(&env);
            if let Ok(sym) = topic_str {
                return sym == symbol_short!("fee");
            }
        }
        false
    });
    assert!(has_fee_event, "Fee event not found");
}
