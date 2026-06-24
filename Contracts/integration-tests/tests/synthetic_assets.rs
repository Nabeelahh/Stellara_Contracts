//! Cross-contract integration tests for the synthetic-assets CDP module.
//!
//! The issue acceptance criteria requires balance-based integration tests that
//! verify collateral moves into the contract on `open_cdp` / `add_collateral`,
//! synthetic tokens really mint into the user's balance on `mint`, are burned
//! on `burn`, debt is burned + collateral paid to the liquidator on `liquidate`,
//! and collateral is returned on `close_cdp`.
//!
//! These tests exercise the *real* contract path through client calls — they
//! spin up the synthetic-assets contract alongside two Stellar Asset Contracts
//! (one for collateral, one for synthetic debt) and assert end-to-end
//! movements of token balances on the ledger.

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    symbol_short,
    testutils::Address as _,
    token::{Client as TokenClient, StellarAssetClient},
    Address, Env,
};
use synthetic_assets::{SyntheticAssetsContract, SyntheticAssetsContractClient};

// Default staleness window for integration tests: 1 day. `register_asset`
// rejects zero; 86_400 is also large enough that the default test-clock
// timestamp of 0 leaves a fresh `update_price` call within window.
const DEFAULT_MAX_AGE: u64 = 86_400;

/// Deploy a fresh synthetic-assets contract, mint some collateral to the user,
/// register a sane asset, and return all the wiring the tests need.
fn boot(
    env: &Env,
    user_balance: i128,
    min_cratio: i128,
    liq_cratio: i128,
    liq_penalty: i128,
) -> (
    SyntheticAssetsContractClient<'_>,
    Address, // contract id
    Address, // collateral token address
    TokenClient<'_>,
    StellarAssetClient<'_>, // collateral minter
    Address, // synthetic token address
    TokenClient<'_>,
    Address, // admin
    Address, // user
) {
    env.mock_all_auths();

    let admin = Address::generate(env);
    let user = Address::generate(env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let sc = SyntheticAssetsContractClient::new(env, &contract_id);

    // Both tokens are real SACs. The contract itself is the admin of the
    // synthetic token so it can mint/burn.
    let coll_addr = env.register_stellar_asset_contract(admin.clone());
    let coll_token = TokenClient::new(env, &coll_addr);
    let coll_admin = StellarAssetClient::new(env, &coll_addr);

    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let synth_token = TokenClient::new(env, &synth_addr);

    sc.initialize(&admin);

    let asset = symbol_short!("sUSD");
    sc.register_asset(
        &admin,
        &asset,
        &min_cratio,
        &liq_cratio,
        &liq_penalty,
        &50_i32,
        &coll_addr,
        &synth_addr,
        &DEFAULT_MAX_AGE,
    );
    sc.update_price(&admin, &asset, &1_000_000); // $1.00
    coll_admin.mint(&user, &user_balance);

    (sc, contract_id, coll_addr, coll_token, coll_admin, synth_addr, synth_token, admin, user)
}

// =============================================================================
// Full lifecycle: open -> mint -> burn -> close
// =============================================================================

#[test]
fn cdp_full_lifecycle_moves_tokens_end_to_end() {
    let env = Env::default();
    let user_balance = 10_000_i128;
    let (sc, contract_id, _coll_addr, coll_token, _coll_admin, _synth_addr, synth_token, _admin, user) =
        boot(&env, user_balance, 15_000, 12_000, 1_300);

    let asset = symbol_short!("sUSD");

    // Open CDP: 1500 collateral moves user -> contract.
    sc.open_cdp(&user, &asset, &1_500_i128);
    assert_eq!(coll_token.balance(&user), 8_500);
    assert_eq!(coll_token.balance(&contract_id), 1_500);

    // Mint 1000 synthetic tokens: contract -> user.
    sc.mint(&user, &asset, &1_000_i128);
    assert_eq!(synth_token.balance(&user), 1_000);

    // Burn 400: user -> burn (synthetic balance drops).
    sc.burn(&user, &asset, &400_i128);
    assert_eq!(synth_token.balance(&user), 600);
    assert_eq!(sc.get_config(&asset).total_minted, 600);

    // Burn the rest: synthetic balance zero.
    sc.burn(&user, &asset, &600_i128);
    assert_eq!(synth_token.balance(&user), 0);
    assert_eq!(sc.get_config(&asset).total_minted, 0);

    // Close CDP: contract -> user (collateral returned).
    let returned = sc.close_cdp(&user, &asset);
    assert_eq!(returned, 1_500);
    assert_eq!(coll_token.balance(&user), user_balance);
    assert_eq!(coll_token.balance(&contract_id), 0);

    let cdp = sc.get_cdp(&user, &asset);
    assert!(!cdp.is_active);
    assert_eq!(cdp.minted_amount, 0);
    assert_eq!(cdp.collateral_amount, 0);
}

// =============================================================================
// Add collateral transfers tokens on top of existing CDP
// =============================================================================

#[test]
fn add_collateral_pulls_more_tokens_into_contract() {
    let env = Env::default();
    let (sc, contract_id, _coll_addr, coll_token, _coll_admin, _synth_addr, _synth_token, _admin, user) =
        boot(&env, 5_000, 15_000, 12_000, 1_300);

    let asset = symbol_short!("sUSD");
    sc.open_cdp(&user, &asset, &1_000_i128);
    assert_eq!(coll_token.balance(&user), 4_000);
    assert_eq!(coll_token.balance(&contract_id), 1_000);

    sc.add_collateral(&user, &asset, &500_i128);
    assert_eq!(coll_token.balance(&user), 3_500);
    assert_eq!(coll_token.balance(&contract_id), 1_500);

    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.collateral_amount, 1_500);
}

// =============================================================================
// Liquidation burns debt and pays liquidator with collateral
// =============================================================================

#[test]
fn liquidation_burns_debt_and_pays_liquidator() {
    let env = Env::default();
    // Sane band: min 150% / liq 120%. Open healthily, raise the oracle price
    // to push the *live* ratio below liq_cratio, then liquidate.
    let (sc, contract_id, _coll_addr, coll_token, _coll_admin, _synth_addr, synth_token, admin, user) =
        boot(&env, 10_000, 15_000, 12_000, 1_300);

    let liquidator = Address::generate(&env);
    let asset = symbol_short!("sUSD");

    // Open CDP. Mint at exactly 150% (1500 collateral, 1000 minted at $1.00).
    sc.open_cdp(&user, &asset, &1_500_i128);
    sc.mint(&user, &asset, &1_000_i128);
    assert_eq!(synth_token.balance(&user), 1_000);

    // Move the synthetic debt to the liquidator before calling liquidate.
    synth_token.transfer(&user, &liquidator, &1_000_i128);

    // Liquidator cannot yet liquidate: live ratio = 15000 >= liq 12000.
    let res_negative = sc.try_liquidate(&liquidator, &user, &asset);
    assert!(res_negative.is_err());
    assert!(sc.get_cdp(&user, &asset).is_active);

    // Raise the oracle price from $1.00 to $1.50.
    //   live_collateral_usd = 1500 * 1e6 / 1.5e6 = 1000
    //   live_cratio         = 1000 * 10000 / 1000 = 10000 < 12000 ✓
    sc.update_price(&admin, &asset, &1_500_000);

    let liq_coll_before = coll_token.balance(&liquidator);
    let contract_coll_before = coll_token.balance(&contract_id);

    // seized = 1500 - 1500*1300/10000 = 1500 - 195 = 1305
    let expected_seized = 1_500_i128 - (1_500_i128 * 1_300 / 10_000);

    let seized = sc.liquidate(&liquidator, &user, &asset);
    assert_eq!(seized, expected_seized);

    // Liquidator paid themselves the seized collateral.
    assert_eq!(coll_token.balance(&liquidator), liq_coll_before + seized);
    // Liquidator burned the synthetic debt.
    assert_eq!(synth_token.balance(&liquidator), 0);
    // Penalty collateral (195) remains in the contract.
    assert_eq!(coll_token.balance(&contract_id), contract_coll_before - seized);

    // Aggregate accounting updated.
    assert_eq!(sc.get_config(&asset).total_minted, 0);

    // CDP position is wiped.
    let cdp = sc.get_cdp(&user, &asset);
    assert!(!cdp.is_active);
    assert_eq!(cdp.minted_amount, 0);
    assert_eq!(cdp.collateral_amount, 0);
}

// =============================================================================
// A fresh CDP cannot be liquidated (collateral_ratio == i128::MAX).
// =============================================================================

#[test]
fn fresh_cdp_is_not_liquidatable() {
    let env = Env::default();
    let (sc, _contract_id, _coll_addr, _coll_token, _coll_admin, _synth_addr, _synth_token, _admin, user) =
        boot(&env, 5_000, 15_000, 12_000, 1_300);

    let liquidator = Address::generate(&env);
    let asset = symbol_short!("sUSD");
    sc.open_cdp(&user, &asset, &1_000_i128);

    // liquidate must fail because the zero-debt CDP reports i128::MAX ratio
    // which is strictly greater than liq_cratio (12_000).
    let res = sc.try_liquidate(&liquidator, &user, &asset);
    assert!(res.is_err());

    // State must remain intact.
    let cdp = sc.get_cdp(&user, &asset);
    assert_eq!(cdp.collateral_amount, 1_000);
    assert_eq!(cdp.minted_amount, 0);
    assert!(cdp.is_active);
}

// =============================================================================
// Minting without an oracle price cannot panic and does not move tokens.
// =============================================================================

#[test]
fn mint_without_oracle_price_returns_error_no_token_movement() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);
    let coll_addr = env.register_stellar_asset_contract(admin.clone());
    let coll_token = TokenClient::new(&env, &coll_addr);
    let coll_admin = StellarAssetClient::new(&env, &coll_addr);
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());
    let synth_token = TokenClient::new(&env, &synth_addr);

    sc.initialize(&admin);
    sc.register_asset(
        &admin,
        &symbol_short!("orph"),
        &15_000_i128,
        &12_000_i128,
        &1_300_i128,
        &50_i32,
        &coll_addr,
        &synth_addr,
        &DEFAULT_MAX_AGE,
    );
    // Note: deliberately NO update_price — oracle_price stays at zero.

    coll_admin.mint(&user, &5_000_i128);
    sc.open_cdp(&user, &symbol_short!("orph"), &1_500_i128);

    let synth_before = synth_token.balance(&user);
    let res = sc.try_mint(&user, &symbol_short!("orph"), &1_000_i128);
    assert!(res.is_err(), "mint must reject when oracle price is unset");

    // No synthetic tokens have been minted to the user.
    assert_eq!(synth_token.balance(&user), synth_before);
    // No collateral moved.
    assert_eq!(coll_token.balance(&user), 3_500);
    // CDP state is unchanged.
    let cdp = sc.get_cdp(&user, &symbol_short!("orph"));
    assert_eq!(cdp.minted_amount, 0);
}

// =============================================================================
// Config validation rejects inverted/liquidation cratios.
// =============================================================================

#[test]
fn register_asset_rejects_liq_cratio_above_min() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, SyntheticAssetsContract);
    let sc = SyntheticAssetsContractClient::new(&env, &contract_id);

    let coll_addr = env.register_stellar_asset_contract(admin.clone());
    let synth_addr = env.register_stellar_asset_contract(contract_id.clone());

    sc.initialize(&admin);

    let res = sc.try_register_asset(
        &admin,
        &symbol_short!("badA"),
        &12_000_i128, // min_cratio
        &15_000_i128, // liq_cratio (bigger than min) — invalid
        &1_300_i128,
        &50_i32,
        &coll_addr,
        &synth_addr,
        &DEFAULT_MAX_AGE,
    );
    assert!(res.is_err());
    // The asset must NOT be registered.
    let cfg = sc.try_get_config(&symbol_short!("badA"));
    assert!(cfg.is_err());
}
