#![cfg(test)]
use super::{SyntheticAssetContract, SyntheticAssetContractClient, Error};
use soroban_sdk::{Env, Address, symbol_short, Symbol};

#[test]
fn test_reject_zero_and_negative_prices() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SyntheticAssetContract);
    let client = SyntheticAssetContractClient::new(&env, &contract_id);
    let asset = symbol_short!("XLM");

    // 1. Assert negative values are blocked explicitly
    let neg_res = client.try_update_price(&asset, &-100);
    assert_eq!(neg_res, Err(Ok(Error::InvalidPrice)));

    // 2. Assert zero pricing entries are blocked explicitly
    let zero_res = client.try_update_price(&asset, &0);
    assert_eq!(zero_res, Err(Ok(Error::InvalidPrice)));

    // 3. Verify standard positive operations function cleanly
    let success_res = client.try_update_price(&asset, &150);
    assert!(success_res.is_ok());
}

#[test]
fn test_operation_fails_without_valid_price() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SyntheticAssetContract);
    let client = SyntheticAssetContractClient::new(&env, &contract_id);
    
    let user = Address::generate(&env);
    let asset = symbol_short!("USDC");

    env.mock_all_auths();

    // Minting path must fail safely when no valid price registry exists yet
    let mint_res = client.try_mint(&user, &asset, &10000);
    assert_eq!(mint_res, Err(Ok(Error::AssetNotInitialized)));
}