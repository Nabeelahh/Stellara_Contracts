#![no_std]

use shared::events::{
    extended_topics, AssetRegisteredEvent, CdpClosedEvent, CdpLiquidatedEvent, CdpOpenedEvent,
    CollateralAddedEvent, PriceUpdatedEvent,
};
use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidAmount = 4,
    InsufficientCollateral = 5,
    BelowMinCratio = 6,
    CDPNotFound = 7,
    NotLiquidatable = 8,
    AssetNotFound = 9,
    InvalidPrice = 10,
    PriceStale = 11,
    // PR #802 sanity checks on registration parameters. Appended at the end
    // so existing ABI codes for InvalidPrice (10) and PriceStale (11) are
    // preserved across the merge.
    InvalidConfig = 12,
}

#[contracttype]
#[derive(Clone)]
pub struct CDP {
    pub owner: Address,
    pub collateral_amount: i128, // in base units
    pub minted_amount: i128,     // synthetic tokens minted
    pub collateral_ratio: i128,  // scaled by 10000 (15000 = 150%)
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct SyntheticConfig {
    pub oracle_price: i128,     // price scaled by 1_000_000
    pub min_cratio: i128,       // scaled by 10000 (15000 = 150%)
    pub liq_cratio: i128,       // scaled by 10000 (12000 = 120%)
    pub liq_penalty: i128,      // scaled by 10000 (1300 = 13%)
    pub stability_fee_bps: i32, // annual fee in bps (200 = 2%)
    pub total_minted: i128,
    pub is_active: bool,
    pub collateral_token: Address,  // token accepted as collateral
    pub synthetic_token: Address,   // SAC minted/burned for synthetic debt
    pub last_updated: u64,          // ledger timestamp of last valid oracle update
    pub price_max_age_seconds: u64, // max age before the price is considered stale
}

mod keys {
    use soroban_sdk::{symbol_short, Symbol};
    pub const ADMIN: Symbol = symbol_short!("admin");
}

#[contract]
pub struct SyntheticAssetsContract;

#[contractimpl]
impl SyntheticAssetsContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&keys::ADMIN) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&keys::ADMIN, &admin);
        Ok(())
    }

    /// Register a synthetic asset with its collateral and synthetic token addresses
    pub fn register_asset(
        env: Env,
        caller: Address,
        asset_symbol: Symbol,
        min_cratio: i128,
        liq_cratio: i128,
        liq_penalty: i128,
        stability_fee_bps: i32,
        collateral_token: Address,
        synthetic_token: Address,
        price_max_age_seconds: u64,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        // Sanity-check configuration to prevent unsafe parameters at registration
        // time. We require:
        //   * min_cratio > liq_cratio  (so a freshly minted position cannot be
        //     immediately liquidatable — liq_cratio > min_cratio would let a user
        //     mint at exactly min_cratio and have an under-collateralized CDP),
        //   * liq_cratio > 0           (otherwise the position can never be
        //     liquidatable),
        //   * liq_penalty in [0, 10000] (0%..=100%; values above 100% would let
        //     the liquidator seize more collateral than the CDP holds),
        //   * stability_fee_bps >= 0   (bps is u32 semantics; negative bps is
        //     nonsensical).
        if min_cratio <= liq_cratio {
            return Err(Error::InvalidConfig);
        }
        if liq_cratio <= 0 {
            return Err(Error::InvalidConfig);
        }
        if liq_penalty < 0 || liq_penalty > 10000 {
            return Err(Error::InvalidConfig);
        }
        if stability_fee_bps < 0 || stability_fee_bps > 10000 {
            return Err(Error::InvalidConfig);
        }

        let config = SyntheticConfig {
            oracle_price: 0,
            min_cratio,
            liq_cratio,
            liq_penalty,
            stability_fee_bps,
            total_minted: 0,
            is_active: true,
            collateral_token,
            synthetic_token,
            last_updated: 0,
            price_max_age_seconds,
        };
        env.storage().persistent().set(&asset_symbol, &config);

        env.events().publish(
            (extended_topics::ASSET_REGISTERED,),
            AssetRegisteredEvent {
                asset_symbol: asset_symbol.clone(),
                registered_by: caller,
                collateral_ratio: min_cratio as u32,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Update oracle price (called by authorized oracle)
    pub fn update_price(
        env: Env,
        caller: Address,
        asset_symbol: Symbol,
        new_price: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        // Reject non-positive prices to prevent division-by-zero in CDP math
        // and to keep the oracle from silently feeding bogus data downstream.
        if new_price <= 0 {
            return Err(Error::InvalidPrice);
        }

        let mut config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        let old_price = config.oracle_price;
        config.oracle_price = new_price;
        config.last_updated = env.ledger().timestamp();
        env.storage().persistent().set(&asset_symbol, &config);

        env.events().publish(
            (extended_topics::PRICE_UPDATED,),
            PriceUpdatedEvent {
                asset_symbol,
                old_price,
                new_price,
                updated_by: caller,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Open CDP: transfer collateral from owner into the contract
    pub fn open_cdp(
        env: Env,
        owner: Address,
        asset_symbol: Symbol,
        collateral_amount: i128,
    ) -> Result<(), Error> {
        owner.require_auth();

        if collateral_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        let cdp = CDP {
            owner: owner.clone(),
            collateral_amount,
            minted_amount: 0,
            // A zero-debt position is effectively infinitely healthy; represent
            // it with i128::MAX so downstream ratio comparisons never report a
            // misleading 0% collateralization for a freshly opened but un-minted
            // CDP.
            collateral_ratio: i128::MAX,
            is_active: true,
        };
        env.storage().persistent().set(&cdp_key, &cdp);

        // Pull collateral from owner into the contract. Storage written
        // first so any reentrant observation of this contract's state
        // already reflects the ownership change before the token
        // movement settles (PR #802 hardening).
        TokenClient::new(&env, &config.collateral_token)
            .transfer(&owner, &env.current_contract_address(), &collateral_amount);

        env.events().publish(
            (extended_topics::CDP_OPENED,),
            CdpOpenedEvent {
                owner: owner.clone(),
                asset_symbol,
                collateral_amount,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Mint synthetic tokens against collateral
    pub fn mint(
        env: Env,
        owner: Address,
        asset_symbol: Symbol,
        mint_amount: i128,
    ) -> Result<i128, Error> {
        owner.require_auth();

        if mint_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        Self::require_valid_price(&env, &config)?;

        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        let mut cdp: CDP = env
            .storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)?;

        let new_minted = cdp.minted_amount + mint_amount;
        let collateral_usd = cdp.collateral_amount * 1_000_000 / config.oracle_price;
        let cratio = collateral_usd * 10000 / new_minted;

        if cratio < config.min_cratio {
            return Err(Error::BelowMinCratio);
        }

        cdp.minted_amount = new_minted;
        cdp.collateral_ratio = cratio;

        let mut updated_config = config.clone();
        updated_config.total_minted += mint_amount;

        env.storage().persistent().set(&cdp_key, &cdp);
        env.storage()
            .persistent()
            .set(&asset_symbol, &updated_config);

        // Mint synthetic tokens to the owner
        StellarAssetClient::new(&env, &config.synthetic_token).mint(&owner, &mint_amount);

        Ok(new_minted)
    }

    /// Burn synthetic tokens to reduce debt
    pub fn burn(
        env: Env,
        owner: Address,
        asset_symbol: Symbol,
        burn_amount: i128,
    ) -> Result<(), Error> {
        owner.require_auth();

        if burn_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        Self::require_valid_price(&env, &config)?;

        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        let mut cdp: CDP = env
            .storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)?;

        if burn_amount > cdp.minted_amount {
            return Err(Error::InvalidAmount);
        }

        // Update CDP and aggregate state before performing the external token
        // burn so the on-chain accounting matches the token movement. (Soroban
        // rolls back atomically on panic, so a failed burn will still revert
        // the storage write.)
        cdp.minted_amount -= burn_amount;

        if cdp.minted_amount > 0 {
            if config.oracle_price <= 0 {
                // The asset was originally minted, so a subsequent price reset
                // to zero should not crash the contract on burn — treat as
                // unhealthy (ratio 0) and let governance / oracle recovery
                // processes decide what to do next.
                cdp.collateral_ratio = 0;
            } else {
                let collateral_usd =
                    cdp.collateral_amount * 1_000_000 / config.oracle_price;
                cdp.collateral_ratio = collateral_usd * 10000 / cdp.minted_amount;
            }
        } else {
            cdp.collateral_ratio = i128::MAX;
        }

        let mut updated_config = config.clone();
        updated_config.total_minted -= burn_amount;

        env.storage().persistent().set(&cdp_key, &cdp);
        env.storage()
            .persistent()
            .set(&asset_symbol, &updated_config);

        // PR #802: actually burn the user's synthetic tokens so the
        // ledger balance matches the debt reduction recorded above.
        TokenClient::new(&env, &config.synthetic_token).burn(&owner, &burn_amount);

        Ok(())
    }

    /// Add more collateral to improve health
    pub fn add_collateral(
        env: Env,
        owner: Address,
        asset_symbol: Symbol,
        amount: i128,
    ) -> Result<(), Error> {
        owner.require_auth();

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        Self::require_valid_price(&env, &config)?;

        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        let mut cdp: CDP = env
            .storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)?;

        cdp.collateral_amount += amount;

        if cdp.minted_amount > 0 {
            if config.oracle_price <= 0 {
                cdp.collateral_ratio = 0;
            } else {
                let collateral_usd =
                    cdp.collateral_amount * 1_000_000 / config.oracle_price;
                cdp.collateral_ratio = collateral_usd * 10000 / cdp.minted_amount;
            }
        }

        env.storage().persistent().set(&cdp_key, &cdp);

        // Interaction: pull additional collateral from owner into the contract.
        TokenClient::new(&env, &config.collateral_token)
            .transfer(&owner, &env.current_contract_address(), &amount);

        env.events().publish(
            (extended_topics::COLLATERAL_ADDED,),
            CollateralAddedEvent {
                owner,
                asset_symbol,
                amount,
                new_ratio: cdp.collateral_ratio as u32,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(())
    }

    /// Liquidate an undercollateralized CDP
    pub fn liquidate(
        env: Env,
        liquidator: Address,
        cdp_owner: Address,
        asset_symbol: Symbol,
    ) -> Result<i128, Error> {
        liquidator.require_auth();

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        Self::require_valid_price(&env, &config)?;

        let cdp_key = Self::cdp_key(&cdp_owner, &asset_symbol);
        let mut cdp: CDP = env
            .storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)?;

        // Recompute the *live* ratio from current state. `cdp.collateral_ratio`
        // is a mint-time snapshot that is not refreshed by `update_price`, so
        // an oracle movement is only visible through the live recomputation
        // below:
        //   * zero debt       => effectively infinitely healthy (MAX),
        //                        so the CDP is never liquidatable;
        //   * zero oracle     => immediately liquidatable (live cratio = 0);
        //   * otherwise       => (collateral * 1e6 / price * 10000) / debt.
        let live_cratio: i128 = if cdp.minted_amount <= 0 {
            i128::MAX
        } else if config.oracle_price <= 0 {
            0
        } else {
            let collateral_usd =
                cdp.collateral_amount * 1_000_000 / config.oracle_price;
            collateral_usd * 10000 / cdp.minted_amount
        };
        if live_cratio >= config.liq_cratio {
            return Err(Error::NotLiquidatable);
        }

        let penalty_collateral = cdp.collateral_amount * config.liq_penalty / 10000;
        let seized = cdp
            .collateral_amount
            .min(cdp.collateral_amount - penalty_collateral);

        let debt = cdp.minted_amount;

        let mut updated_config = config.clone();
        updated_config.total_minted -= debt;

        cdp.is_active = false;
        cdp.minted_amount = 0;
        cdp.collateral_amount = 0;

        env.storage().persistent().set(&cdp_key, &cdp);
        env.storage()
            .persistent()
            .set(&asset_symbol, &updated_config);

        // Liquidator burns the debt tokens to repay the position
        TokenClient::new(&env, &config.synthetic_token).burn(&liquidator, &debt);

        // Transfer seized collateral to the liquidator
        TokenClient::new(&env, &config.collateral_token).transfer(
            &env.current_contract_address(),
            &liquidator,
            &seized,
        );

        env.events().publish(
            (extended_topics::CDP_LIQUIDATED,),
            CdpLiquidatedEvent {
                owner: cdp_owner,
                liquidator,
                asset_symbol,
                collateral_seized: seized,
                debt_repaid: debt,
                timestamp: env.ledger().timestamp(),
            },
        );

        Ok(seized)
    }

    /// Close a CDP with zero debt and return collateral
    pub fn close_cdp(env: Env, owner: Address, asset_symbol: Symbol) -> Result<i128, Error> {
        owner.require_auth();

        let config: SyntheticConfig = env
            .storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)?;

        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        let mut cdp: CDP = env
            .storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)?;

        if cdp.minted_amount > 0 {
            return Err(Error::InsufficientCollateral);
        }

        let returned = cdp.collateral_amount;
        cdp.is_active = false;
        cdp.collateral_amount = 0;

        env.storage().persistent().set(&cdp_key, &cdp);

        // Return collateral to owner
        TokenClient::new(&env, &config.collateral_token).transfer(
            &env.current_contract_address(),
            &owner,
            &returned,
        );

        env.events().publish(
            (extended_topics::CDP_CLOSED,),
            CdpClosedEvent {
                owner,
                asset_symbol,
                collateral_returned: returned,
                timestamp: env.ledger().timestamp(),
            },
        );
        Ok(returned)
    }

    /// View CDP info
    pub fn get_cdp(env: Env, owner: Address, asset_symbol: Symbol) -> Result<CDP, Error> {
        let cdp_key = Self::cdp_key(&owner, &asset_symbol);
        env.storage()
            .persistent()
            .get(&cdp_key)
            .ok_or(Error::CDPNotFound)
    }

    /// View asset config
    pub fn get_config(env: Env, asset_symbol: Symbol) -> Result<SyntheticConfig, Error> {
        env.storage()
            .persistent()
            .get(&asset_symbol)
            .ok_or(Error::AssetNotFound)
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// Ensure the stored oracle price is strictly positive, has been initialized,
    /// and has not aged beyond the per-asset `price_max_age_seconds` window.
    ///
    /// Called by every CDP operation that depends on the oracle price so that
    /// division-by-zero and stale-price scenarios cannot trap users.
    fn require_valid_price(env: &Env, config: &SyntheticConfig) -> Result<(), Error> {
        // `oracle_price <= 0` covers both "never initialized" (register_asset
        // seeds 0) and any explicit zero/negative update (rejected by
        // update_price itself). We intentionally do NOT gate on
        // `last_updated == 0` here: at Soroban's default test-clock value of
        // 0 a fresh `update_price` legitimately stamps last_updated to 0, and
        // conflating that with "uninitialized" would brick every test that
        // touches mint/burn/add_collateral/liquidate without bumping the
        // ledger. Staleness is enforced separately below.
        if config.oracle_price <= 0 {
            return Err(Error::InvalidPrice);
        }
        let now = env.ledger().timestamp();
        // saturating_sub guards against any future-dated `last_updated` values.
        if now.saturating_sub(config.last_updated) > config.price_max_age_seconds {
            return Err(Error::PriceStale);
        }
        Ok(())
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&keys::ADMIN)
            .ok_or(Error::NotInitialized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn cdp_key(owner: &Address, asset: &Symbol) -> (Address, Symbol) {
        (owner.clone(), asset.clone())
    }
}

#[cfg(test)]
mod test;
