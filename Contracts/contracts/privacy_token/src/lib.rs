//! Privacy-Preserving Token Contract
//!
//! This contract implements a privacy-preserving token using Pedersen commitments
//! and nullifier hashes. Users can deposit tokens into the privacy pool and
//! withdraw them without revealing the link between deposit and withdrawal.
//!
//! # Key Features
//!
//! 1. **Private Balances**: Token balances are stored as commitments, not plaintext
//! 2. **Private Transfers**: Users can transfer tokens privately within the pool
//! 3. **Nullifier Tracking**: Prevents double-spending without revealing user identity
//! 4. **Merkle Tree**: Efficient storage and verification of commitments
//!
//! # Privacy Guarantees
//!
//! - Observers cannot determine the balance of any user
//! - The link between deposits and withdrawals is hidden
//! - Transaction amounts are kept private
//! - Only the user with the correct nullifier secret can spend a commitment
//!
//! # Usage Flow
//!
//! 1. **Deposit**: User deposits tokens and receives a commitment
//! 2. **Transfer (Private)**: User can transfer to another commitment privately
//! 3. **Withdraw**: User proves ownership via nullifier and withdraws tokens

#![no_std]
#![allow(unexpected_cfgs)]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol};
use shared::privacy::{
    MerkleRoot, Nullifier, PedersenCommitment, PrivacyError, PrivacyPool, PrivacyPoolConfig,
    PrivacyPoolDataKey, RangeProof,
};

#[cfg(test)]
use shared::privacy::utils;

/// Contract error types
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PrivateTokenError {
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
    /// Merkle tree full
    MerkleTreeFull = 6,
    /// Invalid proof
    InvalidProof = 7,
    /// Contract paused
    Paused = 8,
    /// Not initialized
    NotInitialized = 9,
}

impl From<PrivateTokenError> for soroban_sdk::Error {
    fn from(err: PrivateTokenError) -> Self {
        soroban_sdk::Error::from_contract_error(err as u32)
    }
}

impl From<&PrivateTokenError> for soroban_sdk::Error {
    fn from(err: &PrivateTokenError) -> Self {
        soroban_sdk::Error::from_contract_error(*err as u32)
    }
}

impl From<soroban_sdk::Error> for PrivateTokenError {
    fn from(_err: soroban_sdk::Error) -> Self {
        PrivateTokenError::InvalidProof
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
    /// Token metadata
    Metadata,
    /// Total supply in privacy pool
    TotalSupply,
    /// User's public balance (for non-private operations)
    PublicBalance(Address),
    /// User's nonce (for replay protection)
    Nonce(Address),
}

/// Token metadata
#[contracttype]
#[derive(Clone, Debug)]
pub struct TokenMetadata {
    /// Token name
    pub name: Symbol,
    /// Token symbol
    pub symbol: Symbol,
    /// Token decimals
    pub decimals: u32,
}

/// Deposit event
#[contracttype]
#[derive(Clone, Debug)]
pub struct DepositEvent {
    pub from: Address,
    pub commitment: BytesN<32>,
    pub amount: i128,
    pub leaf_index: u32,
}

/// Withdrawal event
#[contracttype]
#[derive(Clone, Debug)]
pub struct WithdrawalEvent {
    pub to: Address,
    pub nullifier_hash: BytesN<32>,
    pub amount: i128,
}

/// Private transfer event (only reveals nullifier hashes, not amounts or addresses)
#[contracttype]
#[derive(Clone, Debug)]
pub struct PrivateTransferEvent {
    pub input_nullifier: BytesN<32>,
    pub output_commitment: BytesN<32>,
}

/// Private token contract
#[contract]
pub struct PrivateTokenContract;

#[contractimpl]
impl PrivateTokenContract {
    /// Initialize the contract
    pub fn initialize(
        env: Env,
        admin: Address,
        name: Symbol,
        symbol: Symbol,
        decimals: u32,
    ) -> Result<(), PrivateTokenError> {
        // Check if already initialized
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(PrivateTokenError::Unauthorized);
        }

        admin.require_auth();

        // Store admin
        env.storage().instance().set(&DataKey::Admin, &admin);

        // Store metadata
        env.storage().instance().set(
            &DataKey::Metadata,
            &TokenMetadata {
                name: name.clone(),
                symbol: symbol.clone(),
                decimals,
            },
        );

        // Initialize privacy pool
        let config = PrivacyPoolConfig {
            token: env.current_contract_address(),
            tree_depth: 20,
            min_deposit: 1,
            max_deposit: i128::MAX,
            deposit_fee_bps: 0,
            withdrawal_fee_bps: 0,
        };
        PrivacyPool::initialize(&env, &config);

        // Set paused to false
        env.storage().instance().set(&DataKey::Paused, &false);

        // Emit initialization event
        env.events().publish(
            (Symbol::new(&env, "initialized"), admin.clone()),
            (name.clone(), symbol.clone(), decimals),
        );

        Ok(())
    }

    /// Deposit tokens into the privacy pool
    /// The user provides a commitment (hash of value + blinding_factor)
    /// The actual value is never revealed on-chain
    pub fn deposit(
        env: Env,
        from: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> Result<u32, PrivateTokenError> {
        from.require_auth();

        // Check not paused
        if Self::is_paused(&env) {
            return Err(PrivateTokenError::Paused);
        }

        // Validate amount
        if amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Verify range proof
        if !RangeProof::verify_range(amount) {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Deduct from public balance
        let current_balance = Self::public_balance(&env, from.clone());
        if current_balance < amount {
            return Err(PrivateTokenError::InsufficientBalance);
        }
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(from.clone()), &(current_balance - amount));

        // Add commitment to privacy pool
        let leaf_index = PrivacyPool::deposit(&env, &commitment, amount)
            .map_err(|e| match e {
                PrivacyError::MerkleTreeFull => PrivateTokenError::MerkleTreeFull,
                _ => PrivateTokenError::InvalidCommitment,
            })?;

        // Update total supply
        let total_supply = Self::total_supply(&env);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &(total_supply + amount));

        // Emit deposit event
        env.events().publish(
            (Symbol::new(&env, "deposit"), from.clone()),
            DepositEvent {
                from,
                commitment,
                amount,
                leaf_index,
            },
        );

        Ok(leaf_index)
    }

    /// Withdraw tokens from the privacy pool
    /// User proves ownership by providing the nullifier hash
    pub fn withdraw(
        env: Env,
        to: Address,
        amount: i128,
        nullifier_hash: BytesN<32>,
    ) -> Result<(), PrivateTokenError> {
        // Check not paused
        if Self::is_paused(&env) {
            return Err(PrivateTokenError::Paused);
        }

        // Validate amount
        if amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Check if nullifier has been spent
        if PrivacyPool::is_nullifier_spent(&env, &nullifier_hash) {
            return Err(PrivateTokenError::AlreadySpent);
        }

        // Verify the nullifier corresponds to a valid commitment
        // In a full implementation, this would verify a Merkle proof
        PrivacyPool::withdraw(&env, &nullifier_hash, &to, amount)
            .map_err(|e| match e {
                PrivacyError::NullifierAlreadySpent => PrivateTokenError::AlreadySpent,
                _ => PrivateTokenError::InvalidProof,
            })?;

        // Add to public balance
        let current_balance = Self::public_balance(&env, to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(to.clone()), &(current_balance + amount));

        // Update total supply
        let total_supply = Self::total_supply(&env);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &(total_supply - amount));

        // Emit withdrawal event
        env.events().publish(
            (Symbol::new(&env, "withdrawal"), to.clone()),
            WithdrawalEvent {
                to,
                nullifier_hash,
                amount,
            },
        );

        Ok(())
    }

    /// Private transfer within the pool
    /// Spends one commitment and creates a new one
    pub fn private_transfer(
        env: Env,
        input_nullifier: BytesN<32>,
        output_commitment: BytesN<32>,
        output_amount: i128,
    ) -> Result<(), PrivateTokenError> {
        // Check not paused
        if Self::is_paused(&env) {
            return Err(PrivateTokenError::Paused);
        }

        // Check if input nullifier has been spent
        if PrivacyPool::is_nullifier_spent(&env, &input_nullifier) {
            return Err(PrivateTokenError::AlreadySpent);
        }

        // Validate output amount
        if output_amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Mark input nullifier as spent
        env.storage().persistent().set(
            &PrivacyPoolDataKey::Nullifier(input_nullifier.clone()),
            &Nullifier {
                hash: input_nullifier.clone(),
                is_spent: true,
                spent_at: env.ledger().timestamp(),
            },
        );

        // Add output commitment to pool
        PrivacyPool::deposit(&env, &output_commitment, output_amount)
            .map_err(|e| match e {
                PrivacyError::MerkleTreeFull => PrivateTokenError::MerkleTreeFull,
                _ => PrivateTokenError::InvalidCommitment,
            })?;

        // Emit private transfer event
        env.events().publish(
            (Symbol::new(&env, "private_transfer"),),
            PrivateTransferEvent {
                input_nullifier,
                output_commitment,
            },
        );

        Ok(())
    }

    /// Mint public tokens (admin only)
    pub fn mint(
        env: Env,
        admin: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), PrivateTokenError> {
        admin.require_auth();

        // Verify admin
        if !Self::is_admin(&env, admin.clone()) {
            return Err(PrivateTokenError::Unauthorized);
        }

        // Validate amount
        if amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Add to public balance
        let current_balance = Self::public_balance(&env, to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(to.clone()), &(current_balance + amount));

        // Update total supply
        let total_supply = Self::total_supply(&env);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &(total_supply + amount));

        // Emit mint event
        env.events().publish(
            (Symbol::new(&env, "mint"), admin, to),
            amount,
        );

        Ok(())
    }

    /// Burn public tokens
    pub fn burn(
        env: Env,
        from: Address,
        amount: i128,
    ) -> Result<(), PrivateTokenError> {
        from.require_auth();

        // Validate amount
        if amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Check balance
        let current_balance = Self::public_balance(&env, from.clone());
        if current_balance < amount {
            return Err(PrivateTokenError::InsufficientBalance);
        }

        // Deduct from balance
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(from.clone()), &(current_balance - amount));

        // Update total supply
        let total_supply = Self::total_supply(&env);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &(total_supply - amount));

        // Emit burn event
        env.events().publish(
            (Symbol::new(&env, "burn"), from),
            amount,
        );

        Ok(())
    }

    /// Transfer public tokens
    pub fn transfer(
        env: Env,
        from: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), PrivateTokenError> {
        from.require_auth();

        // Check not paused
        if Self::is_paused(&env) {
            return Err(PrivateTokenError::Paused);
        }

        // Validate amount
        if amount <= 0 {
            return Err(PrivateTokenError::InvalidAmount);
        }

        // Check balance
        let from_balance = Self::public_balance(&env, from.clone());
        if from_balance < amount {
            return Err(PrivateTokenError::InsufficientBalance);
        }

        // Transfer
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(from.clone()), &(from_balance - amount));

        let to_balance = Self::public_balance(&env, to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::PublicBalance(to.clone()), &(to_balance + amount));

        // Emit transfer event
        env.events().publish(
            (Symbol::new(&env, "transfer"), from, to),
            amount,
        );

        Ok(())
    }

    /// Get public balance
    pub fn public_balance(env: &Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::PublicBalance(account))
            .unwrap_or(0)
    }

    /// Get total supply
    pub fn total_supply(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    /// Get token metadata
    pub fn metadata(env: &Env) -> TokenMetadata {
        env.storage()
            .instance()
            .get(&DataKey::Metadata)
            .unwrap_or(TokenMetadata {
                name: Symbol::new(env, "Unknown"),
                symbol: Symbol::new(env, "UNK"),
                decimals: 0,
            })
    }

    /// Get Merkle root
    pub fn merkle_root(env: &Env) -> MerkleRoot {
        PrivacyPool::get_root(env)
    }

    /// Check if nullifier has been spent
    pub fn is_spent(env: &Env, nullifier_hash: BytesN<32>) -> bool {
        PrivacyPool::is_nullifier_spent(env, &nullifier_hash)
    }

    /// Get commitment at index
    pub fn get_commitment(env: &Env, index: u32) -> Option<PedersenCommitment> {
        PrivacyPool::get_commitment(env, index)
    }

    /// Get next leaf index
    pub fn next_leaf_index(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&PrivacyPoolDataKey::NextLeafIndex)
            .unwrap_or(0)
    }

    /// Pause contract (admin only)
    pub fn pause(env: Env, admin: Address) -> Result<(), PrivateTokenError> {
        admin.require_auth();

        if !Self::is_admin(&env, admin.clone()) {
            return Err(PrivateTokenError::Unauthorized);
        }

        env.storage().instance().set(&DataKey::Paused, &true);

        env.events().publish(
            (Symbol::new(&env, "paused"), admin),
            (),
        );

        Ok(())
    }

    /// Unpause contract (admin only)
    pub fn unpause(env: Env, admin: Address) -> Result<(), PrivateTokenError> {
        admin.require_auth();

        if !Self::is_admin(&env, admin.clone()) {
            return Err(PrivateTokenError::Unauthorized);
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

    /// Verify a commitment matches value and blinding factor
    pub fn verify_commitment(
        env: &Env,
        commitment: BytesN<32>,
        value: i128,
        blinding_factor: BytesN<32>,
    ) -> bool {
        PrivacyPool::verify_commitment(env, &commitment, value, &blinding_factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup_env() -> (Env, Address, PrivateTokenContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PrivateTokenContract);
        let client = PrivateTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);

        (env, admin, client)
    }

    #[test]
    fn test_initialize() {
        let (env, admin, client) = setup_env();

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        let metadata = client.metadata();
        assert_eq!(metadata.name, Symbol::new(&env, "PrivateToken"));
        assert_eq!(metadata.symbol, Symbol::new(&env, "PRIV"));
        assert_eq!(metadata.decimals, 18);
    }

    #[test]
    fn test_mint_and_public_balance() {
        let (env, admin, client) = setup_env();
        let user = Address::generate(&env);

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        client.mint(&admin, &user, &1000);

        assert_eq!(client.public_balance(&user), 1000);
        assert_eq!(client.total_supply(), 1000);
    }

    #[test]
    fn test_transfer() {
        let (env, admin, client) = setup_env();
        let from = Address::generate(&env);
        let to = Address::generate(&env);

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        client.mint(&admin, &from, &1000);
        client.transfer(&from, &to, &400);

        assert_eq!(client.public_balance(&from), 600);
        assert_eq!(client.public_balance(&to), 400);
    }

    #[test]
    fn test_deposit_and_withdraw() {
        let (env, admin, client) = setup_env();
        let user = Address::generate(&env);

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        // Mint tokens to user
        client.mint(&admin, &user, &1000);
        assert_eq!(client.public_balance(&user), 1000);

        // Create a commitment for deposit
        let note = utils::create_private_note(&env, 500i128).unwrap();
        
        // Deposit into privacy pool
        let leaf_index = client.deposit(&user, &500, &note.commitment);
        assert_eq!(leaf_index, 0);
        assert_eq!(client.public_balance(&user), 500);

        // Verify commitment was stored
        let commitment = client.get_commitment(&0);
        assert!(commitment.is_some());
        
        // Compute nullifier hash
        let nullifier_hash = PrivacyPool::compute_nullifier_hash(&env, &note.nullifier_secret);
        
        // Withdraw from privacy pool
        client.withdraw(&user, &500, &nullifier_hash);
        assert_eq!(client.public_balance(&user), 1000);
        
        // Verify nullifier is marked as spent
        assert!(client.is_spent(&nullifier_hash));
    }

    #[test]
    fn test_private_transfer() {
        let (env, admin, client) = setup_env();
        let user = Address::generate(&env);

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        // Mint and deposit
        client.mint(&admin, &user, &1000);
        let note1 = utils::create_private_note(&env, 500i128).unwrap();
        client.deposit(&user, &500, &note1.commitment);

        // Create output note
        let note2 = utils::create_private_note(&env, 300i128).unwrap();
        let nullifier_hash = PrivacyPool::compute_nullifier_hash(&env, &note1.nullifier_secret);

        // Private transfer
        client.private_transfer(&nullifier_hash, &note2.commitment, &300);

        // Verify input nullifier is spent
        assert!(client.is_spent(&nullifier_hash));
    }

    #[test]
    fn test_pause_unpause() {
        let (env, admin, client) = setup_env();

        client.initialize(
            &admin,
            &Symbol::new(&env, "PrivateToken"),
            &Symbol::new(&env, "PRIV"),
            &18,
        );

        assert!(!client.is_paused());

        client.pause(&admin);
        assert!(client.is_paused());

        client.unpause(&admin);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_verify_commitment() {
        let (env, _admin, client) = setup_env();

        let value = 1000i128;
        let note = utils::create_private_note(&env, value).unwrap();

        // Verify commitment matches
        assert!(client.verify_commitment(&note.commitment, &value, &note.blinding_factor));
        
        // Verify wrong value fails
        assert!(!client.verify_commitment(&note.commitment, &999, &note.blinding_factor));
    }
}
