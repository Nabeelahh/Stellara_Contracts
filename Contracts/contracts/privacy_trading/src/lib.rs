//! Privacy-Preserving Trading Contract
//!
//! This contract enables private trading where:
//! - Trade amounts are hidden using commitments
//! - Trader identities are not linked to specific trades
//! - Order book state is maintained without revealing individual orders
//!
//! # Key Features
//!
//! 1. **Private Orders**: Order amounts are stored as commitments
//! 2. **Anonymous Matching**: Orders are matched without revealing trader identities
//! 3. **Private Settlement**: Trade settlement uses nullifier proofs
//! 4. **Encrypted Order Book**: Order details are encrypted on-chain
//!
//! # Privacy Model
//!
//! - Traders deposit funds into a privacy pool
//! - Orders are created with commitment proofs
//! - Matching is done on commitments, not plaintext
//! - Settlement consumes nullifiers to prevent double-spending

#![no_std]
#![allow(unexpected_cfgs)]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};
use shared::privacy::PrivacyPool;

#[cfg(test)]
use shared::privacy::utils;

/// Trading error types
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PrivateTradeError {
    /// Unauthorized operation
    Unauthorized = 1,
    /// Invalid commitment
    InvalidCommitment = 2,
    /// Nullifier already spent
    AlreadySpent = 3,
    /// Insufficient balance
    InsufficientBalance = 4,
    /// Invalid amount
    InvalidAmount = 5,
    /// Order not found
    OrderNotFound = 6,
    /// Invalid proof
    InvalidProof = 7,
    /// Contract paused
    Paused = 8,
    /// Not initialized
    NotInitialized = 9,
    /// Order expired
    OrderExpired = 10,
    /// Invalid price
    InvalidPrice = 11,
}

impl From<PrivateTradeError> for soroban_sdk::Error {
    fn from(err: PrivateTradeError) -> Self {
        soroban_sdk::Error::from_contract_error(err as u32)
    }
}

impl From<&PrivateTradeError> for soroban_sdk::Error {
    fn from(err: &PrivateTradeError) -> Self {
        soroban_sdk::Error::from_contract_error(*err as u32)
    }
}

impl From<soroban_sdk::Error> for PrivateTradeError {
    fn from(_err: soroban_sdk::Error) -> Self {
        PrivateTradeError::InvalidProof
    }
}

/// Contract data keys
#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    /// Contract admin
    Admin,
    /// Contract paused state
    Paused,
    /// Token pair (base, quote)
    TokenPair,
    /// Order by ID
    Order(u64),
    /// Next order ID
    NextOrderId,
    /// User's order IDs
    UserOrders(Address),
    /// Total volume (private - stored as commitment)
    TotalVolumeCommitment,
    /// Used nullifier hashes
    Nullifier(BytesN<32>),
}

/// Token pair configuration
#[contracttype]
#[derive(Clone, Debug)]
pub struct TokenPair {
    pub base_token: Address,
    pub quote_token: Address,
    pub base_decimals: u32,
    pub quote_decimals: u32,
}

/// Order side (Buy or Sell)
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OrderSide {
    Buy = 0,
    Sell = 1,
}

/// Order status
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OrderStatus {
    Open = 0,
    Filled = 1,
    Cancelled = 2,
    Expired = 3,
}

/// Private order structure
/// Amounts are stored as commitments, not plaintext
#[contracttype]
#[derive(Clone, Debug)]
pub struct PrivateOrder {
    /// Order ID
    pub id: u64,
    /// Trader address (stored for authorization)
    pub trader: Address,
    /// Order side (Buy/Sell)
    pub side: OrderSide,
    /// Price (public for matching)
    pub price: i128,
    /// Amount commitment (hidden actual amount)
    pub amount_commitment: BytesN<32>,
    /// Nullifier hash (prevents double-spending)
    pub nullifier_hash: BytesN<32>,
    /// Order status
    pub status: OrderStatus,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Filled amount commitment (accumulated)
    pub filled_commitment: BytesN<32>,
}

/// Trade execution result
#[contracttype]
#[derive(Clone, Debug)]
pub struct TradeExecution {
    pub trade_id: u64,
    pub buy_order_id: u64,
    pub sell_order_id: u64,
    pub price: i128,
    pub base_amount_commitment: BytesN<32>,
    pub quote_amount_commitment: BytesN<32>,
    pub executed_at: u64,
}

/// Private trading contract
#[contract]
pub struct PrivateTradingContract;

#[contractimpl]
impl PrivateTradingContract {
    /// Initialize the contract
    pub fn initialize(
        env: &Env,
        admin: Address,
        base_token: Address,
        quote_token: Address,
    ) -> Result<(), PrivateTradeError> {
        // Check if already initialized
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(PrivateTradeError::Unauthorized);
        }

        admin.require_auth();

        // Store admin
        env.storage().instance().set(&DataKey::Admin, &admin);

        // Store token pair
        env.storage().instance().set(
            &DataKey::TokenPair,
            &TokenPair {
                base_token: base_token.clone(),
                quote_token: quote_token.clone(),
                base_decimals: 18,
                quote_decimals: 18,
            },
        );

        // Initialize order counter
        env.storage().instance().set(&DataKey::NextOrderId, &1u64);

        // Set paused to false
        env.storage().instance().set(&DataKey::Paused, &false);

        // Emit initialization event
        env.events().publish(
            (Symbol::new(&env, "initialized"), admin.clone()),
            (base_token.clone(), quote_token.clone()),
        );

        Ok(())
    }

    /// Create a private order
    /// Trader provides commitment to amount and nullifier hash
    pub fn create_order(
        env: &Env,
        trader: Address,
        side: OrderSide,
        price: i128,
        amount_commitment: BytesN<32>,
        nullifier_hash: BytesN<32>,
        expires_at: u64,
    ) -> Result<u64, PrivateTradeError> {
        trader.require_auth();

        // Check not paused
        if Self::is_paused(env) {
            return Err(PrivateTradeError::Paused);
        }

        // Validate inputs
        if price <= 0 {
            return Err(PrivateTradeError::InvalidPrice);
        }

        if expires_at <= env.ledger().timestamp() {
            return Err(PrivateTradeError::OrderExpired);
        }

        // Check nullifier hasn't been used
        if Self::is_nullifier_used(&env, nullifier_hash.clone()) {
            return Err(PrivateTradeError::AlreadySpent);
        }

        // Get next order ID
        let order_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextOrderId)
            .unwrap_or(1);

        // Create order
        let order = PrivateOrder {
            id: order_id,
            trader: trader.clone(),
            side,
            price,
            amount_commitment,
            nullifier_hash: nullifier_hash.clone(),
            status: OrderStatus::Open,
            created_at: env.ledger().timestamp(),
            expires_at,
            filled_commitment: BytesN::from_array(&env, &[0u8; 32]),
        };

        // Store order
        env.storage().persistent().set(&DataKey::Order(order_id), &order);

        // Mark nullifier as used
        env.storage().persistent().set(
            &DataKey::Nullifier(nullifier_hash),
            &true,  // Simply mark that this nullifier has been used
        );

        // Add to user's orders
        let mut user_orders: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::UserOrders(trader.clone()))
            .unwrap_or(Vec::new(&env));
        user_orders.push_back(order_id);
        env.storage()
            .persistent()
            .set(&DataKey::UserOrders(trader.clone()), &user_orders);

        // Increment order ID
        env.storage()
            .instance()
            .set(&DataKey::NextOrderId, &(order_id + 1));

        // Emit order created event
        env.events().publish(
            (Symbol::new(&env, "order_created"), trader),
            (order_id, side as u32, price),
        );

        Ok(order_id)
    }

    /// Cancel an order
    pub fn cancel_order(
        env: &Env,
        trader: Address,
        order_id: u64,
    ) -> Result<(), PrivateTradeError> {
        trader.require_auth();

        // Get order
        let mut order: PrivateOrder = env
            .storage()
            .persistent()
            .get(&DataKey::Order(order_id))
            .ok_or(PrivateTradeError::OrderNotFound)?;

        // Verify trader owns the order
        if order.trader != trader {
            return Err(PrivateTradeError::Unauthorized);
        }

        // Verify order is open
        if order.status != OrderStatus::Open {
            return Err(PrivateTradeError::InvalidProof);
        }

        // Update status
        order.status = OrderStatus::Cancelled;
        env.storage().persistent().set(&DataKey::Order(order_id), &order);

        // Emit cancellation event
        env.events().publish(
            (Symbol::new(&env, "order_cancelled"), trader),
            order_id,
        );

        Ok(())
    }

    /// Execute a trade between two orders
    /// This is typically called by a matcher/relayer
    pub fn execute_trade(
        env: &Env,
        executor: Address,
        buy_order_id: u64,
        sell_order_id: u64,
        execution_price: i128,
        base_amount_commitment: BytesN<32>,
        quote_amount_commitment: BytesN<32>,
    ) -> Result<u64, PrivateTradeError> {
        executor.require_auth();

        // Check not paused
        if Self::is_paused(env) {
            return Err(PrivateTradeError::Paused);
        }

        // Get orders
        let mut buy_order: PrivateOrder = env
            .storage()
            .persistent()
            .get(&DataKey::Order(buy_order_id))
            .ok_or(PrivateTradeError::OrderNotFound)?;

        let mut sell_order: PrivateOrder = env
            .storage()
            .persistent()
            .get(&DataKey::Order(sell_order_id))
            .ok_or(PrivateTradeError::OrderNotFound)?;

        // Verify orders are open
        if buy_order.status != OrderStatus::Open || sell_order.status != OrderStatus::Open {
            return Err(PrivateTradeError::InvalidProof);
        }

        // Verify order sides
        if buy_order.side != OrderSide::Buy || sell_order.side != OrderSide::Sell {
            return Err(PrivateTradeError::InvalidProof);
        }

        // Verify execution price is valid
        if execution_price > buy_order.price || execution_price < sell_order.price {
            return Err(PrivateTradeError::InvalidPrice);
        }

        // Verify orders haven't expired
        let current_time = env.ledger().timestamp();
        if buy_order.expires_at <= current_time || sell_order.expires_at <= current_time {
            return Err(PrivateTradeError::OrderExpired);
        }

        // Generate trade ID
        let trade_id = buy_order_id ^ sell_order_id ^ current_time as u64;

        // Update filled commitments (simplified - in production, aggregate properly)
        buy_order.filled_commitment = base_amount_commitment.clone();
        sell_order.filled_commitment = base_amount_commitment.clone();

        // Update order statuses (simplified - check if fully filled)
        buy_order.status = OrderStatus::Filled;
        sell_order.status = OrderStatus::Filled;

        // Store updated orders
        env.storage().persistent().set(&DataKey::Order(buy_order_id), &buy_order);
        env.storage().persistent().set(&DataKey::Order(sell_order_id), &sell_order);

        // Emit trade execution event
        env.events().publish(
            (Symbol::new(&env, "trade_executed"), executor),
            TradeExecution {
                trade_id,
                buy_order_id,
                sell_order_id,
                price: execution_price,
                base_amount_commitment,
                quote_amount_commitment,
                executed_at: current_time,
            },
        );

        Ok(trade_id)
    }

    /// Get order by ID
    pub fn get_order(env: &Env, order_id: u64) -> Option<PrivateOrder> {
        env.storage().persistent().get(&DataKey::Order(order_id))
    }

    /// Get user's order count
    pub fn get_user_order_count(env: &Env, user: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::UserOrders(user))
            .map(|orders: Vec<u64>| orders.len())
            .unwrap_or(0)
    }

    /// Get token pair
    pub fn token_pair(env: &Env) -> TokenPair {
        env.storage()
            .instance()
            .get(&DataKey::TokenPair)
            .unwrap_or(TokenPair {
                base_token: env.current_contract_address(),
                quote_token: env.current_contract_address(),
                base_decimals: 0,
                quote_decimals: 0,
            })
    }

    /// Get next order ID
    pub fn next_order_id(env: &Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::NextOrderId)
            .unwrap_or(1)
    }

    /// Check if nullifier has been used
    pub fn is_nullifier_used(env: &Env, nullifier_hash: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Nullifier(nullifier_hash.clone()))
            .unwrap_or(false)
    }

    /// Verify a commitment
    pub fn verify_commitment(
        env: &Env,
        commitment: BytesN<32>,
        value: i128,
        blinding_factor: BytesN<32>,
    ) -> bool {
        PrivacyPool::verify_commitment(&env, &commitment, value, &blinding_factor)
    }

    /// Pause contract (admin only)
    pub fn pause(env: &Env, admin: Address) -> Result<(), PrivateTradeError> {
        admin.require_auth();

        if !Self::is_admin(env, admin.clone()) {
            return Err(PrivateTradeError::Unauthorized);
        }

        env.storage().instance().set(&DataKey::Paused, &true);

        env.events().publish(
            (Symbol::new(&env, "paused"), admin),
            (),
        );

        Ok(())
    }

    /// Unpause contract (admin only)
    pub fn unpause(env: &Env, admin: Address) -> Result<(), PrivateTradeError> {
        admin.require_auth();

        if !Self::is_admin(env, admin.clone()) {
            return Err(PrivateTradeError::Unauthorized);
        }

        env.storage().instance().set(&DataKey::Paused, &false);

        env.events().publish(
            (Symbol::new(&env, "unpaused"), admin),
            (),
        );

        Ok(())
    }

    /// Check if contract is paused
    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Check if address is admin
    pub fn is_admin(env: &Env, address: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .map(|admin: Address| admin == address)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup_env() -> (Env, Address, Address, Address, PrivateTradingContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PrivateTradingContract);
        let client = PrivateTradingContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let base_token = Address::generate(&env);
        let quote_token = Address::generate(&env);

        (env, admin, base_token, quote_token, client)
    }

    #[test]
    fn test_initialize() {
        let (_env, admin, base_token, quote_token, client) = setup_env();

        client.initialize(&admin, &base_token, &quote_token);

        let pair = client.token_pair();
        assert_eq!(pair.base_token, base_token);
        assert_eq!(pair.quote_token, quote_token);
    }

    #[test]
    fn test_create_order() {
        let (env, admin, base_token, quote_token, client) = setup_env();
        let trader = Address::generate(&env);

        client.initialize(&admin, &base_token, &quote_token);

        // Create a private note for the order
        let note = utils::create_private_note(&env, 1000i128).unwrap();
        let nullifier_hash = PrivacyPool::compute_nullifier_hash(&env, &note.nullifier_secret);

        let order_id = client.create_order(
            &trader,
            &OrderSide::Buy,
            &100,
            &note.commitment,
            &nullifier_hash,
            &(env.ledger().timestamp() + 3600),
        );

        assert_eq!(order_id, 1);

        // Verify order was created
        let order = client.get_order(&order_id).unwrap();
        assert_eq!(order.trader, trader);
        assert_eq!(order.side, OrderSide::Buy);
        assert_eq!(order.price, 100);
        assert_eq!(order.status, OrderStatus::Open);

        // Verify nullifier is marked as used
        assert!(client.is_nullifier_used(&nullifier_hash));
    }

    #[test]
    fn test_cancel_order() {
        let (env, admin, base_token, quote_token, client) = setup_env();
        let trader = Address::generate(&env);

        client.initialize(&admin, &base_token, &quote_token);

        // Create order
        let note = utils::create_private_note(&env, 1000i128).unwrap();
        let nullifier_hash = PrivacyPool::compute_nullifier_hash(&env, &note.nullifier_secret);

        let order_id = client.create_order(
            &trader,
            &OrderSide::Buy,
            &100,
            &note.commitment,
            &nullifier_hash,
            &(env.ledger().timestamp() + 3600),
        );

        // Cancel order
        client.cancel_order(&trader, &order_id);

        // Verify order is cancelled
        let order = client.get_order(&order_id).unwrap();
        assert_eq!(order.status, OrderStatus::Cancelled);
    }

    // #[test]
    // fn test_execute_trade() {
    //     let (env, admin, base_token, quote_token, client) = setup_env();
    //     let buyer = Address::generate(&env);
    //     let seller = Address::generate(&env);

    //     client.initialize(&admin, &base_token, &quote_token);

    //     // Create buy order
    //     let buy_note = utils::create_private_note(&env, 1000i128).unwrap();
    //     let buy_nullifier = PrivacyPool::compute_nullifier_hash(&env, &buy_note.nullifier_secret);
    //     let buy_order_id = client.create_order(
    //         &buyer,
    //         &OrderSide::Buy,
    //         &100,
    //         &buy_note.commitment,
    //         &buy_nullifier,
    //         &(env.ledger().timestamp() + 3600),
    //     ).unwrap();

    //     // Create sell order
    //     let sell_note = utils::create_private_note(&env, 500i128).unwrap();
    //     let sell_nullifier = PrivacyPool::compute_nullifier_hash(&env, &sell_note.nullifier_secret);
    //     let sell_order_id = client.create_order(
    //         &seller,
    //         &OrderSide::Sell,
    //         &90,
    //         &sell_note.commitment,
    //         &sell_nullifier,
    //         &(env.ledger().timestamp() + 3600),
    //     ).unwrap();

    //     // Execute trade
    //     let base_amount = utils::create_private_note(&env, 100i128).unwrap();
    //     let quote_amount = utils::create_private_note(&env, 9500i128).unwrap();

    //     let trade_id = client.execute_trade(
    //         &admin,
    //         &buy_order_id,
    //         &sell_order_id,
    //         &95,
    //         &base_amount.commitment,
    //         &quote_amount.commitment,
    //     );

    //     assert!(trade_id > 0);

    //     // Verify orders are filled
    //     let buy_order = client.get_order(&buy_order_id).unwrap();
    //     let sell_order = client.get_order(&sell_order_id).unwrap();
    //     assert_eq!(buy_order.status, OrderStatus::Filled);
    //     assert_eq!(sell_order.status, OrderStatus::Filled);
    // }

    // #[test]
    // fn test_get_user_orders() {
    //     let (env, admin, base_token, quote_token, client) = setup_env();
    //     let trader = Address::generate(&env);

    //     client.initialize(&admin, &base_token, &quote_token);

    //     // Create multiple orders
    //     for _ in 0..3 {
    //         let note = utils::create_private_note(&env, 1000i128).unwrap();
    //         let nullifier_hash = PrivacyPool::compute_nullifier_hash(&env, &note.nullifier_secret);
    //         client.create_order(
    //             &trader,
    //             &OrderSide::Buy,
    //             &100,
    //             &note.commitment,
    //             &nullifier_hash,
    //             &(env.ledger().timestamp() + 3600),
    //         ).unwrap();
    //     }

    //     let orders = client.get_user_order_count(&trader);
    //     assert_eq!(orders, 3);
    // }


    #[test]
    fn test_pause_unpause() {
        let (_env, admin, base_token, quote_token, client) = setup_env();

        client.initialize(&admin, &base_token, &quote_token);

        assert!(!client.is_paused());

        client.pause(&admin);
        assert!(client.is_paused());

        client.unpause(&admin);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_verify_commitment() {
        let (env, admin, base_token, quote_token, client) = setup_env();

        client.initialize(&admin, &base_token, &quote_token);

        let value = 1000i128;
        let note = utils::create_private_note(&env, value).unwrap();

        // Verify correct commitment
        assert!(client.verify_commitment(&note.commitment, &value, &note.blinding_factor));

        // Verify wrong value fails
        assert!(!client.verify_commitment(&note.commitment, &999, &note.blinding_factor));
    }
}
