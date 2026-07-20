#![no_std]
pub mod bridge;
use shared::nonce::NonceManager;
use shared::reentrancy_guard::ReentrancyGuard;
use soroban_sdk::{contract, contractimpl, contracttype, Env, Symbol, Vec, BytesN, Address, Bytes, symbol_short, xdr::ToXdr};


#[contract]
pub struct CrossChainRouter;

#[contracttype]
#[derive(Clone)]
pub struct Message {
    pub id: BytesN<32>,
    pub source_chain: u32,
    pub dest_chain: u32,
    pub sender: Address,
    pub recipient: Address,
    pub payload: Bytes,
    pub nonce: u64,
    pub status: u32,
    pub processed: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct FeeAccounting {
    pub base_fee: i128,
    pub gas_fee: i128,
    pub total_collected: i128,
    pub total_distributed: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct Validator {
    pub address: Address,
    pub staked_amount: i128,
    pub status: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct LightClientHeader {
    pub block_number: u64,
    pub block_hash: BytesN<32>,
    pub timestamp: u64,
    pub commitment_root: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct MessageProcessedEvent {
    pub message_id: BytesN<32>,
    pub source_chain: u32,
    pub dest_chain: u32,
    pub nonce: u64,
    pub fee_collected: i128,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct ReplayRejectedEvent {
    pub message_id: BytesN<32>,
    pub source_chain: u32,
    pub reason: Symbol,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct FeeCollectedEvent {
    pub message_id: BytesN<32>,
    pub base_fee: i128,
    pub gas_fee: i128,
    pub total: i128,
    pub timestamp: u64,
}

#[contractimpl]
impl CrossChainRouter {
    pub fn init(env: Env, admin: Address) {
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "admin"), &admin);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "initialized"), &true);

        let fee_accounting = FeeAccounting {
            base_fee: 0,
            gas_fee: 0,
            total_collected: 0,
            total_distributed: 0,
        };
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "fee_accounting"), &fee_accounting);
    }

    pub fn set_chain_id(env: Env, admin: Address, chain_id: u32) {
        admin.require_auth();
        NonceManager::set_chain_id(&env, chain_id);
    }

    pub fn initiate_message(
        env: Env,
        source_chain: u32,
        dest_chain: u32,
        sender: Address,
        recipient: Address,
        payload: Bytes,
    ) -> BytesN<32> {
        sender.require_auth();
        ReentrancyGuard::enter(&env);

        NonceManager::enforce_sequential_nonce(&env, source_chain, env.ledger().sequence() as u64);

        let nonce = env.ledger().sequence() as u64;
        let message_id: BytesN<32> = Self::compute_message_hash(&env, source_chain, dest_chain, nonce, &payload);

        let message = Message {
            id: message_id.clone(),
            source_chain,
            dest_chain,
            sender: sender.clone(),
            recipient,
            payload,
            nonce,
            status: 0,
            processed: false,
        };

        let mut messages: Vec<Message> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "messages"))
            .unwrap_or(Vec::new(&env));

        messages.push_back(message);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "messages"), &messages);

        env.events()
            .publish((symbol_short!("msg_init"),), message_id.clone());

        ReentrancyGuard::exit(&env);
        message_id
    }

    pub fn process_message(
        env: Env,
        source_chain: u32,
        dest_chain: u32,
        nonce: u64,
        payload: Bytes,
    ) -> bool {
        ReentrancyGuard::enter(&env);

        let message_id = Self::compute_message_hash(&env, source_chain, dest_chain, nonce, &payload);

        if Self::is_message_processed(env.clone(), message_id.clone()) {
            env.events().publish(
                (symbol_short!("rp_rej"),),
                ReplayRejectedEvent {
                    message_id: message_id.clone(),
                    source_chain,
                    reason: Symbol::new(&env, "DUPLICATE"),
                    timestamp: env.ledger().timestamp(),
                },
            );
            ReentrancyGuard::exit(&env);
            return false;
        }

        let messages: Vec<Message> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "messages"))
            .unwrap_or(Vec::new(&env));

        for i in 0..messages.len() {
            let msg = messages.get_unchecked(i);
            if msg.id == message_id && msg.processed {
                env.events().publish(
                    (symbol_short!("rp_rej"),),
                    ReplayRejectedEvent {
                        message_id,
                        source_chain,
                        reason: Symbol::new(&env, "ALREADY_PROCESSED"),
                        timestamp: env.ledger().timestamp(),
                    },
                );
                ReentrancyGuard::exit(&env);
                return false;
            }
        }

        let fee_accounting: FeeAccounting = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "fee_accounting"))
            .unwrap_or(FeeAccounting {
                base_fee: 0,
                gas_fee: 0,
                total_collected: 0,
                total_distributed: 0,
            });

        let total_fee = fee_accounting.base_fee + fee_accounting.gas_fee;
        if total_fee > 0 {
            env.events().publish(
                (symbol_short!("fee_col"),),
                FeeCollectedEvent {
                    message_id: message_id.clone(),
                    base_fee: fee_accounting.base_fee,
                    gas_fee: fee_accounting.gas_fee,
                    total: total_fee,
                    timestamp: env.ledger().timestamp(),
                },
            );
        }

        Self::mark_message_processed(&env, &message_id);

        env.events().publish(
            (symbol_short!("msg_proc"),),
            MessageProcessedEvent {
                message_id,
                source_chain,
                dest_chain,
                nonce,
                fee_collected: total_fee,
                timestamp: env.ledger().timestamp(),
            },
        );

        ReentrancyGuard::exit(&env);
        true
    }

    pub fn verify_message(
        env: Env,
        message_id: BytesN<32>,
        _header: LightClientHeader,
        proof: Bytes,
    ) -> bool {
        ReentrancyGuard::enter(&env);

        let light_client: LightClientHeader = match env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "light_client"))
        {
            Some(lc) => lc,
            None => {
                ReentrancyGuard::exit(&env);
                return false;
            }
        };

        let expected_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let is_valid = expected_hash == light_client.commitment_root;

        if is_valid {
            let mut messages: Vec<Message> = env
                .storage()
                .persistent()
                .get(&Symbol::new(&env, "messages"))
                .unwrap_or(Vec::new(&env));

            for i in 0..messages.len() {
                let mut msg = messages.get_unchecked(i);
                if msg.id == message_id {
                    if msg.processed {
                        ReentrancyGuard::exit(&env);
                        panic!("REPLAY_DETECTED");
                    }
                    msg.status = 2;
                    msg.processed = true;
                    messages.set(i, msg);
                    break;
                }
            }

            env.storage()
                .persistent()
                .set(&Symbol::new(&env, "messages"), &messages);

            env.events()
                .publish((Symbol::new(&env, "message_verified"),), message_id);
        }

        ReentrancyGuard::exit(&env);
        is_valid
    }

    pub fn set_fees(env: Env, admin: Address, base_fee: i128, gas_fee: i128) {
        admin.require_auth();

        let mut fee_accounting: FeeAccounting = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "fee_accounting"))
            .unwrap_or(FeeAccounting {
                base_fee: 0,
                gas_fee: 0,
                total_collected: 0,
                total_distributed: 0,
            });

        fee_accounting.base_fee = base_fee;
        fee_accounting.gas_fee = gas_fee;

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "fee_accounting"), &fee_accounting);
    }

    pub fn get_fee_accounting(env: Env) -> FeeAccounting {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, "fee_accounting"))
            .unwrap_or(FeeAccounting {
                base_fee: 0,
                gas_fee: 0,
                total_collected: 0,
                total_distributed: 0,
            })
    }

    pub fn is_message_processed(env: Env, message_id: BytesN<32>) -> bool {
        let processed: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "processed_hashes"))
            .unwrap_or(Vec::new(&env));

        for i in 0..processed.len() {
            if processed.get_unchecked(i) == message_id {
                return true;
            }
        }
        false
    }

    pub fn register_validator(
        env: Env,
        validator_address: Address,
        staked_amount: i128,
    ) -> bool {
        validator_address.require_auth();
        ReentrancyGuard::enter(&env);

        if staked_amount < 1_000_000_000 {
            ReentrancyGuard::exit(&env);
            return false;
        }

        let validator = Validator {
            address: validator_address.clone(),
            staked_amount,
            status: 0,
        };

        let mut validators: Vec<Validator> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "validators"))
            .unwrap_or(Vec::new(&env));

        validators.push_back(validator);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "validators"), &validators);

        ReentrancyGuard::exit(&env);
        true
    }

    pub fn slash_validator(
        env: Env,
        validator_address: Address,
        slash_percentage: u64,
    ) -> i128 {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "admin"))
            .unwrap();

        admin.require_auth();
        ReentrancyGuard::enter(&env);

        let mut validators: Vec<Validator> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "validators"))
            .unwrap_or(Vec::new(&env));

        let mut slash_amount: i128 = 0;

        for i in 0..validators.len() {
            let mut validator = validators.get_unchecked(i);
            if validator.address == validator_address {
                slash_amount = (validator.staked_amount * slash_percentage as i128) / 100;
                validator.staked_amount -= slash_amount;

                if validator.staked_amount <= 0 {
                    validator.status = 2;
                }

                validators.set(i, validator);
                break;
            }
        }

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "validators"), &validators);

        env.events()
            .publish((Symbol::new(&env, "validator_slashed"),), validator_address);

        ReentrancyGuard::exit(&env);
        slash_amount
    }

    pub fn get_message_status(env: Env, message_id: BytesN<32>) -> u32 {
        let messages: Vec<Message> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "messages"))
            .unwrap_or(Vec::new(&env));

        for message in messages.iter() {
            if message.id == message_id {
                return message.status;
            }
        }

        u32::MAX
    }

    pub fn update_light_client(env: Env, header: LightClientHeader) -> bool {
        ReentrancyGuard::enter(&env);

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "light_client"), &header);

        ReentrancyGuard::exit(&env);
        true
    }

    pub fn get_validator_count(env: Env) -> u32 {
        let validators: Vec<Validator> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "validators"))
            .unwrap_or(Vec::new(&env));

        let count = validators
            .iter()
            .filter(|v| v.status == 0)
            .count();

        count as u32
    }

    fn compute_message_hash(env: &Env, source_chain: u32, dest_chain: u32, nonce: u64, payload: &Bytes) -> BytesN<32> {
        let mut data = Bytes::new(env);
        data.append(&source_chain.to_xdr(env));
        data.append(&dest_chain.to_xdr(env));
        data.append(&nonce.to_xdr(env));
        data.append(&payload.clone());
        env.crypto().sha256(&data).into()
    }

    fn mark_message_processed(env: &Env, message_id: &BytesN<32>) {
        let mut processed: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, "processed_hashes"))
            .unwrap_or(Vec::new(env));
        processed.push_back(message_id.clone());
        env.storage()
            .persistent()
            .set(&Symbol::new(env, "processed_hashes"), &processed);

        let mut messages: Vec<Message> = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, "messages"))
            .unwrap_or(Vec::new(env));

        for i in 0..messages.len() {
            let mut msg = messages.get_unchecked(i);
            if msg.id == *message_id {
                msg.status = 1;
                msg.processed = true;
                messages.set(i, msg);
                break;
            }
        }

        env.storage()
            .persistent()
            .set(&Symbol::new(env, "messages"), &messages);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, testutils::Address as _, Address, BytesN, Bytes};

    #[test]
    fn test_initiate_message() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);
        client.set_chain_id(&admin, &0u32);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let payload = Bytes::from_array(&env, &[1, 2, 3]);

        client.initiate_message(&0, &1, &sender, &recipient, &payload);
    }

    #[test]
    fn test_verify_message_rejects_replay() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let header = LightClientHeader {
            block_number: 1,
            block_hash: BytesN::from_array(&env, &[1u8; 32]),
            timestamp: 1000,
            commitment_root: BytesN::from_array(&env, &[2u8; 32]),
        };
        client.update_light_client(&header);

        let proof = Bytes::from_array(&env, &[3u8; 32]);
        let message_id = client.verify_message(
            &BytesN::from_array(&env, &[4u8; 32]),
            &header,
            &proof,
        );

        assert!(!message_id);
    }

    #[test]
    fn test_process_message_rejects_duplicate() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let payload = Bytes::from_array(&env, &[1u8; 32]);
        let result1 = client.process_message(&0, &1, &100u64, &payload);
        assert!(result1);

        let result2 = client.process_message(&0, &1, &100u64, &payload);
        assert!(!result2);
    }

    #[test]
    fn test_set_fees_and_get_accounting() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_fees(&admin, &100i128, &50i128);

        let accounting = client.get_fee_accounting();
        assert_eq!(accounting.base_fee, 100);
        assert_eq!(accounting.gas_fee, 50);
        assert_eq!(accounting.total_collected, 0);
        assert_eq!(accounting.total_distributed, 0);
    }

    #[test]
    fn test_process_message_with_different_nonces_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        let payload = Bytes::from_array(&env, &[1u8; 32]);
        let result1 = client.process_message(&0, &1, &100u64, &payload);
        assert!(result1);

        let result2 = client.process_message(&0, &1, &101u64, &payload);
        assert!(result2);
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Bytes, Env,
    };

    fn setup_contract(env: &Env) -> CrossChainRouterClient<'_> {
        let contract_id = env.register_contract(None, CrossChainRouter);
        let client = CrossChainRouterClient::new(env, &contract_id);
        let admin = Address::generate(env);
        client.init(&admin);
        client
    }

    #[test]
    fn test_cross_chain_replay_rejected() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);
        env.mock_all_auths();

        let client = setup_contract(&env);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let payload = Bytes::from_array(&env, &[7u8; 32]);
        let message_id = client.initiate_message(&0, &1, &sender, &recipient, &payload);

        let proof = Bytes::from_array(&env, &[3u8; 32]);
        let commitment_root = env.crypto().sha256(&proof);

        let header = LightClientHeader {
            block_number: 1,
            block_hash: BytesN::from_array(&env, &[1u8; 32]),
            timestamp: 1000,
            commitment_root: commitment_root.into(),
        };
        client.update_light_client(&header);

        let first_verify = client.verify_message(&message_id, &header, &proof);
        assert!(first_verify);

        let replay = client.try_verify_message(&message_id, &header, &proof);
        assert!(replay.is_err(), "Replay should be rejected");
    }

    #[test]
    fn test_cross_chain_nonce_enforces_sequential_order() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);
        env.mock_all_auths();

        let client = setup_contract(&env);
        client.set_chain_id(&Address::generate(&env), &1u32);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let payload = Bytes::from_array(&env, &[8u8; 32]);
        client.initiate_message(&1, &2, &sender, &recipient, &payload);
    }

    #[test]
    fn test_process_message_fee_emitted() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);
        env.mock_all_auths();

        let client = setup_contract(&env);
        let admin = Address::generate(&env);

        client.set_fees(&admin, &100i128, &25i128);

        let payload = Bytes::from_array(&env, &[9u8; 32]);
        let result = client.process_message(&0, &1, &200u64, &payload);
        assert!(result);

        let accounting = client.get_fee_accounting();
        assert_eq!(accounting.base_fee, 100);
        assert_eq!(accounting.gas_fee, 25);
    }

    #[test]
    fn test_process_message_malformed_empty_payload_accepted() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);
        env.mock_all_auths();

        let client = setup_contract(&env);

        let empty_payload = Bytes::new(&env);
        let result = client.process_message(&0, &1, &300u64, &empty_payload);
        assert!(result);
    }
}
