use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, 
    Address, Env, Vec, Map, BytesN, Bytes, xdr::ToXdr
};
use shared::governance::{GovernanceRole};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    pub admin: Address,
    pub fee_collector: Address,
    pub is_paused: bool,
    pub validator_threshold: u32,
    pub chain_id: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimit {
    pub limit: i128,
    pub window: u64,
    pub current_usage: i128,
    pub last_update: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BridgeError {
    Unauthorized = 3001,
    Paused = 3002,
    RateLimitExceeded = 3003,
    InvalidSignature = 3004,
    ReplayAttack = 3005,
    InsufficientValidators = 3006,
    AlreadyInitialized = 3007,
    NotInitialized = 3008,
    MessageNotVerified = 3009,
    MessageAlreadyProcessed = 3010,
}

#[contract]
pub struct StellaraBridge;

#[contractimpl]
impl StellaraBridge {
    pub fn initialize(env: Env, admin: Address, fee_collector: Address, validator_threshold: u32, chain_id: u32) {
        if env.storage().persistent().has(&symbol_short!("config")) {
            panic!("Already initialized");
        }

        let config = BridgeConfig {
            admin: admin.clone(),
            fee_collector,
            is_paused: false,
            validator_threshold,
            chain_id,
        };

        env.storage().persistent().set(&symbol_short!("config"), &config);

        let mut roles: Map<Address, GovernanceRole> = Map::new(&env);
        roles.set(admin, GovernanceRole::Admin);
        env.storage().persistent().set(&symbol_short!("roles"), &roles);
        env.storage().persistent().set(&symbol_short!("init"), &true);
    }

    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128, dest_chain: u32, recipient: Address) -> BytesN<32> {
        from.require_auth();
        let config: BridgeConfig = Self::get_config_internal(&env);
        if config.is_paused {
            panic!("Bridge paused");
        }

        Self::check_rate_limit(&env, &asset, amount);

        let nonce = env.ledger().sequence() as u64;
        let mut data = Bytes::new(&env);
        data.append(&from.clone().to_xdr(&env));
        data.append(&asset.clone().to_xdr(&env));
        data.append(&amount.to_xdr(&env));
        data.append(&dest_chain.to_xdr(&env));
        data.append(&recipient.clone().to_xdr(&env));
        data.append(&nonce.to_xdr(&env));
        
        let deposit_id: BytesN<32> = env.crypto().sha256(&data).into();

        env.events().publish(
            (symbol_short!("deposit"), from, asset, dest_chain),
            (amount, recipient, deposit_id.clone(), nonce)
        );

        deposit_id
    }

    pub fn withdraw(env: Env, to: Address, asset: Address, amount: i128, source_chain: u32, nonce: u64, signatures: Vec<BytesN<64>>) -> BytesN<32> {
        let config: BridgeConfig = Self::get_config_internal(&env);
        if config.is_paused {
            panic!("Bridge paused");
        }

        let mut data = Bytes::new(&env);
        data.append(&to.clone().to_xdr(&env));
        data.append(&asset.clone().to_xdr(&env));
        data.append(&amount.to_xdr(&env));
        data.append(&source_chain.to_xdr(&env));
        data.append(&nonce.to_xdr(&env));
        
        let message_hash: BytesN<32> = env.crypto().sha256(&data).into();
        
        Self::verify_validator_signatures(&env, &message_hash, &signatures, config.validator_threshold);

        let nonce_key = (symbol_short!("nonce"), source_chain, nonce);
        if env.storage().persistent().has(&nonce_key) {
            panic!("Replay attack");
        }
        env.storage().persistent().set(&nonce_key, &true);

        let withdrawal_id = message_hash;
        env.events().publish(
            (symbol_short!("withdraw"), to, asset, source_chain),
            (amount, withdrawal_id.clone(), nonce)
        );

        withdrawal_id
    }

    pub fn add_validator(env: Env, validator: Address) {
        let config: BridgeConfig = Self::get_config_internal(&env);
        config.admin.require_auth();

        let mut validators: Vec<Address> = env.storage().persistent().get(&symbol_short!("validator")).unwrap_or(Vec::new(&env));
        if !validators.iter().any(|v| v == validator) {
            validators.push_back(validator);
            env.storage().persistent().set(&symbol_short!("validator"), &validators);
        }
    }

    pub fn remove_validator(env: Env, validator: Address) {
        let config: BridgeConfig = Self::get_config_internal(&env);
        config.admin.require_auth();

        let validators: Vec<Address> = env.storage().persistent().get(&symbol_short!("validator")).unwrap_or(Vec::new(&env));
        let mut new_validators = Vec::new(&env);
        for v in validators.iter() {
            if v != validator {
                new_validators.push_back(v);
            }
        }
        env.storage().persistent().set(&symbol_short!("validator"), &new_validators);
    }

    pub fn set_rate_limit(env: Env, asset: Address, limit: i128, window: u64) {
        let config: BridgeConfig = Self::get_config_internal(&env);
        config.admin.require_auth();

        let rl = RateLimit {
            limit,
            window,
            current_usage: 0,
            last_update: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&(symbol_short!("rl"), asset), &rl);
    }

    pub fn set_paused(env: Env, paused: bool) {
        let mut config: BridgeConfig = Self::get_config_internal(&env);
        config.admin.require_auth();
        config.is_paused = paused;
        env.storage().persistent().set(&symbol_short!("config"), &config);
    }

    pub fn get_config(env: Env) -> BridgeConfig {
        Self::get_config_internal(&env)
    }

    fn get_config_internal(env: &Env) -> BridgeConfig {
        env.storage().persistent().get(&symbol_short!("config")).expect("Not initialized")
    }

    fn check_rate_limit(env: &Env, asset: &Address, amount: i128) {
        let rl_key = (symbol_short!("rl"), asset.clone());
        if let Some(mut rl) = env.storage().persistent().get::<_, RateLimit>(&rl_key) {
            let now = env.ledger().timestamp();
            if now >= rl.last_update + rl.window {
                rl.current_usage = 0;
                rl.last_update = now;
            }

            if rl.current_usage + amount > rl.limit {
                panic!("Rate limit exceeded");
            }

            rl.current_usage += amount;
            env.storage().persistent().set(&rl_key, &rl);
        }
    }

    fn verify_validator_signatures(env: &Env, _hash: &BytesN<32>, signatures: &Vec<BytesN<64>>, threshold: u32) {
        if (signatures.len() as u32) < threshold {
            panic!("Insufficient signatures");
        }

        let validators: Vec<Address> = env.storage().persistent().get(&symbol_short!("validator")).unwrap_or(Vec::new(env));
        if (validators.len() as u32) < threshold {
            panic!("Not enough registered validators");
        }
    }
}
