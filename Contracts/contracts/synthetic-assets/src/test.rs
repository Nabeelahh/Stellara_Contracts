#![cfg(test)]

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::Address as _,
    token::{Client as TokenClient, StellarAssetClient},
    Address, Env,
};

fn create_collateral_token(
    env: &Env,
    admin: &Address,
) -> (Address, TokenClient<'static>, StellarAssetClient<'static>) {
    let addr = env.register_stellar_asset_contract(admin.clone());
    (
        addr.clone(),
        TokenClient::new(env, &addr),
        StellarAssetClient::new(env, &addr),
    )
}

fn deploy_contract(env: &Env) -> (Address, SyntheticAssetsContractClient<'static>) {
    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let client = SyntheticAssetsContractClient::new(env, &contract_id);
    (contract_id, client)
}

#[test]
fn test_cdp_full_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    // Contract must be the admin of the synthetic token so it can mint/burn
    let contract_id = env.register_contract(None, SyntheticAssetsContract);

    let (coll_addr, coll_client, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let synth_client = TokenClient::new(&env, &synth_addr);

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("sUSD");
    sc.register_asset(
        &admin, &asset,
        &15000,   // min_cratio: 150%
        &12000,   // liq_cratio: 120%
        &1300,    // liq_penalty: 13%
        &50,
        &coll_addr,
        &synth_addr,
    );
    sc.update_price(&admin, &asset, &1_000_000); // $1.00

    coll_admin.mint(&user, &10000);

    // Open CDP — collateral moves from user to contract
    sc.open_cdp(&user, &asset, &1500);
    assert_eq!(coll_client.balance(&user), 8500);
    assert_eq!(coll_client.balance(&contract_id), 1500);
    // Zero-debt CDP has infinite collateralization ratio (i128::MAX).
    let freshly_opened = sc.get_cdp(&user, &asset);
    assert_eq!(freshly_opened.collateral_amount, 1500);
    assert_eq!(freshly_opened.minted_amount, 0);
    assert!(freshly_opened.is_active);

    // Mint 1000 synthetic tokens
    // cratio = (1500 * 1e6 / 1e6) * 10000 / 1000 = 15000 (exactly 150%)
    sc.mint(&user, &asset, &1000);
    assert_eq!(synth_client.balance(&user), 1000);
    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.collateral_ratio, 15000);

    // Burn 500 tokens — balance halves
    sc.burn(&user, &asset, &500);
    assert_eq!(synth_client.balance(&user), 500);

    // Burn remaining debt before closing
    sc.burn(&user, &asset, &500);
    assert_eq!(synth_client.balance(&user), 0);

    // Close CDP — full collateral returned
    let returned = sc.close_cdp(&user, &asset);
    assert_eq!(returned, 1500);
    assert_eq!(coll_client.balance(&user), 10000);
    assert_eq!(coll_client.balance(&contract_id), 0);

    let cdp = sc.get_cdp(&user, &asset);
    assert!(!cdp.is_active);
}

#[test]
fn test_add_collateral_transfers_tokens() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, coll_client, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("sETH");
    sc.register_asset(&admin, &asset, &15000, &12000, &1300, &50, &coll_addr, &synth_addr);
    sc.update_price(&admin, &asset, &1_000_000);

    coll_admin.mint(&user, &5000);
    sc.open_cdp(&user, &asset, &1000);
    assert_eq!(coll_client.balance(&user), 4000);
    assert_eq!(coll_client.balance(&contract_id), 1000);

    sc.add_collateral(&user, &asset, &500);
    assert_eq!(coll_client.balance(&user), 3500);
    assert_eq!(coll_client.balance(&contract_id), 1500);

    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.collateral_amount, 1500);
}

#[test]
fn test_liquidation_transfers_collateral_to_liquidator() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let liquidator = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, coll_client, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let synth_client = TokenClient::new(&env, &synth_addr);

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("sBTC");
    // Sane band: min 150% > liq 120%. Open healthily at exactly min_cratio,
    // then push the *live* ratio below liq_cratio by raising the oracle price
    // (because the contract's live-ratio formula is `collateral * 1e6 / price`,
    // a higher price makes each unit of collateral worth fewer USD and so the
    // live ratio drops).
    sc.register_asset(
        &admin, &asset,
        &15000_i128, // min_cratio: 150%
        &12000_i128, // liq_cratio: 120%
        &1300_i128,  // liq_penalty: 13%
        &50_i32,
        &coll_addr,
        &synth_addr,
    );
    sc.update_price(&admin, &asset, &1_000_000); // $1.00 base

    coll_admin.mint(&user, &10000);

    sc.open_cdp(&user, &asset, &1500);
    // Mint 1000 against 1500 at oracle=1e6: live ratio = 15000.
    sc.mint(&user, &asset, &1000);

    assert_eq!(coll_client.balance(&user), 8500);
    assert_eq!(synth_client.balance(&user), 1000);

    // First confirm `liquidate` rejects while the position is healthy.
    let res = sc.try_liquidate(&liquidator, &user, &asset);
    assert!(res.is_err());

    // Move the synthetic debt tokens to the liquidator before liquidating.
    synth_client.transfer(&user, &liquidator, &1000_i128);

    // Raise the oracle price to 1.5e6 => live_collateral_usd = 1000 =>
    // live_cratio = 10000 < 12000 (liq_cratio): liquidatable now.
    sc.update_price(&admin, &asset, &1_500_000);

    // seized = 1500 - 1500*1300/10000 = 1500 - 195 = 1305
    let expected_seized = 1500_i128 - (1500_i128 * 1300 / 10000);
    let liq_coll_before = coll_client.balance(&liquidator);

    let seized = sc.liquidate(&liquidator, &user, &asset);

    assert_eq!(seized, expected_seized);
    // Liquidator burned debt tokens
    assert_eq!(synth_client.balance(&liquidator), 0);
    // Liquidator received the seized collateral
    assert_eq!(coll_client.balance(&liquidator), liq_coll_before + seized);
    // Penalty collateral (195) remains in contract
    assert_eq!(coll_client.balance(&contract_id), 1500 - seized);

    // CDP is wiped
    let cdp = sc.get_cdp(&user, &asset);
    assert!(!cdp.is_active);
    assert_eq!(cdp.minted_amount, 0);
    assert_eq!(cdp.collateral_amount, 0);
}

#[test]
fn test_liquidate_rejects_healthy_position() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let liquidator = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, coll_client, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let synth_client = TokenClient::new(&env, &synth_addr);

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("sOK");
    sc.register_asset(
        &admin, &asset,
        &15000_i128,
        &12000_i128,
        &1300_i128,
        &50_i32,
        &coll_addr,
        &synth_addr,
    );
    sc.update_price(&admin, &asset, &1_000_000);

    coll_admin.mint(&user, &5_000_i128);
    sc.open_cdp(&user, &asset, &1500_i128);
    sc.mint(&user, &asset, &1000_i128);

    // Position is healthy at ratio 15000 >= liq 12000: liquidation must fail.
    synth_client.transfer(&user, &liquidator, &1000_i128);
    let res = sc.try_liquidate(&liquidator, &user, &asset);
    assert!(res.is_err());
    let cdp = sc.get_cdp(&user, &asset);
    assert!(cdp.is_active);
    assert_eq!(cdp.minted_amount, 1000);
    // State intact: collateral still parked in the contract, liquidator's
    // synthetic tokens are untouched because the burn is gated by the same
    // pre-condition.
    assert_eq!(coll_client.balance(&contract_id), 1500);
    assert_eq!(synth_client.balance(&liquidator), 1000);
}

// ---------------------------------------------------------------------------
// New tests for the contract hardening introduced alongside #802.
// ---------------------------------------------------------------------------

#[test]
fn test_register_asset_rejects_inverted_cr_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, _) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("bad");

    // min_cratio <= liq_cratio is rejected (would mint liquidatable positions).
    let res = sc.try_register_asset(
        &admin, &asset,
        &12000_i128, // min_cratio
        &15000_i128, // liq_cratio — bigger than min: invalid
        &1300_i128,
        &50_i32,
        &coll_addr,
        &synth_addr,
    );
    assert!(res.is_err());
}

#[test]
fn test_register_asset_rejects_zero_or_negative_liq_cratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, _) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("zliq");
    let res = sc.try_register_asset(
        &admin, &asset,
        &15000_i128,
        &0_i128, // liq_cratio = 0: invalid
        &1300_i128,
        &50_i32,
        &coll_addr,
        &synth_addr,
    );
    assert!(res.is_err());
}

#[test]
fn test_register_asset_rejects_out_of_range_penalty() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, _) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("huge");
    // >100% penalty would let liquidators seize more than the CDP holds.
    let res = sc.try_register_asset(
        &admin, &asset,
        &15000_i128,
        &12000_i128,
        &15000_i128, // 150% penalty: invalid
        &50_i32,
        &coll_addr,
        &synth_addr,
    );
    assert!(res.is_err());
}

#[test]
fn test_mint_fails_when_oracle_price_not_set() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);
    sc.register_asset(&admin, &symbol_short!("orph"), &15000, &12000, &1300, &50, &coll_addr, &synth_addr);
    // No update_price — oracle_price stays at zero

    coll_admin.mint(&user, &5000);
    sc.open_cdp(&user, &symbol_short!("orph"), &1500);

    let res = sc.try_mint(&user, &symbol_short!("orph"), &1000_i128);
    assert!(res.is_err(), "mint must reject when oracle price is zero");
}

#[test]
fn test_open_cdp_zero_debt_infinite_ratio() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);

    let asset = symbol_short!("fresh");
    sc.register_asset(&admin, &asset, &15000, &12000, &1300, &50, &coll_addr, &synth_addr);
    sc.update_price(&admin, &asset, &1_000_000);

    coll_admin.mint(&user, &1000);
    sc.open_cdp(&user, &asset, &500);

    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.minted_amount, 0);
    // We represent infinite health for a zero-debt CDP with i128::MAX so
    // downstream ratio checks never report a spurious 0% collateralization.
    assert_eq!(cdp.collateral_ratio, i128::MAX);
}

#[test]
fn test_burn_clears_total_minted_in_config() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);
    let asset = symbol_short!("tot");
    sc.register_asset(&admin, &asset, &15000, &12000, &1000, &50, &coll_addr, &synth_addr);
    sc.update_price(&admin, &asset, &1_000_000);

    coll_admin.mint(&user, &5000);
    sc.open_cdp(&user, &asset, &1500);
    sc.mint(&user, &asset, &1000);

    assert_eq!(sc.get_config(&asset).total_minted, 1000);
    sc.burn(&user, &asset, &400);
    assert_eq!(sc.get_config(&asset).total_minted, 600);
    sc.burn(&user, &asset, &600);
    assert_eq!(sc.get_config(&asset).total_minted, 0);
}

#[test]
fn test_double_spend_attempt_over_burning_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let (coll_addr, _, coll_admin) = create_collateral_token(&env, &admin);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());

    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    sc.initialize(&admin);
    let asset = symbol_short!("dbl");
    sc.register_asset(&admin, &asset, &15000, &12000, &1000, &50, &coll_addr, &synth_addr);
    sc.update_price(&admin, &asset, &1_000_000);

    coll_admin.mint(&user, &5000);
    sc.open_cdp(&user, &asset, &2000);
    sc.mint(&user, &asset, &1000);

    // Try to burn more than minted → rejected.
    let res = sc.try_burn(&user, &asset, &1001_i128);
    assert!(res.is_err());

    // Burn exactly minted → succeeds.
    sc.burn(&user, &asset, &1000);
    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.minted_amount, 0);
}
