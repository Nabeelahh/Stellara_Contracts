#![cfg(test)]

use super::*;
use soroban_sdk::{Env, testutils::Address as _, token};

#[test]
fn test_trade_fee_collection() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, TradingContract);
    let client = TradingContractClient::new(&env, &contract_id);

    // Create a token for fees
    let issuer = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(issuer);
    let token_client = token::Client::new(&env, &token_contract_id);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_contract_id);

    let trader = Address::generate(&env);
    let recipient = Address::generate(&env);
    let fee_amount = 100;

    // Mint tokens to trader
    token_admin_client.mint(&trader, &1000);

    // Perform trade with sufficient balance
    let res = client.trade(&trader, &token_contract_id, &fee_amount, &recipient);
    assert!(res.is_ok());

    // Verify fee transfer
    assert_eq!(token_client.balance(&trader), 900);
    assert_eq!(token_client.balance(&recipient), 100);
}

#[test]
fn test_trade_insufficient_fee() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, TradingContract);
    let client = TradingContractClient::new(&env, &contract_id);

    let issuer = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(issuer);
    // No minting, balance is 0

    let trader = Address::generate(&env);
    let recipient = Address::generate(&env);
    let fee_amount = 100;

    // Perform trade with insufficient balance
    // use try_trade to catch error
    let res = client.try_trade(&trader, &token_contract_id, &fee_amount, &recipient);
    
    assert!(res.is_err());
    
    match res {
        Err(Ok(err)) => {
            // Check if it is the expected contract error
            assert_eq!(err, FeeError::InsufficientBalance);
        },
        _ => panic!("Expected contract error"),
    }
}
