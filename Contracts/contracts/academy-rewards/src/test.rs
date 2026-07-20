#[cfg(test)]
mod test {
    use crate::{AcademyRewardsContract, AcademyRewardsContractClient, ContractError};
    use shared::circuit_breaker::CircuitBreakerConfig;
    use soroban_sdk::{testutils::{Address as _, Ledger}, symbol_short, Address, Env, String};

    fn default_cb_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            max_volume_per_period: 1_000_000,
            max_tx_count_per_period: 100,
            period_duration: 3600,
        }
    }

    #[test]
    fn test_initialization() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());
    }

    #[test]
    fn test_badge_lifecycle() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());

        // Create badge type
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500, // 5% discount
            &10,  // 10 max redemptions
            &0,   // Never expires
        );

        // Mint badge
        client.mint_badge(&admin, &user, &1);

        // Check discount
        let discount = client.get_user_discount(&user);
        assert_eq!(discount, 500);

        // Get badge info
        let badge = client.get_user_badge(&user).unwrap();
        assert_eq!(badge.badge_type, 1);
        assert_eq!(badge.discount_bps, 500);
        assert_eq!(badge.redeemed_count, 0);

        // Check total minted
        let total = client.get_total_minted(&1);
        assert_eq!(total, 1);
    }

    #[test]
    fn test_redemption() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());

        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &3, // 3 max redemptions
            &0,
        );

        client.mint_badge(&admin, &user, &1);

        // Redeem badge
        let tx_hash = String::from_str(&env, "tx_001");
        let discount = client.redeem_badge(&user, &tx_hash);

        assert_eq!(discount, 500);

        // Check updated badge
        let badge = client.get_user_badge(&user).unwrap();
        assert_eq!(badge.redeemed_count, 1);

        // Check redemption history
        let history = client.get_redemption_history(&user, &0).unwrap();
        assert_eq!(history.badge_type, 1);
        assert_eq!(history.discount_applied, 500);
    }

    #[test]
    fn test_prevent_double_redemption() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());
        client.create_badge_type(&admin, &1, &String::from_str(&env, "Bronze"), &500, &10, &0);
        client.mint_badge(&admin, &user, &1);

        let tx_hash = String::from_str(&env, "tx_001");

        // First redemption - should succeed
        client.redeem_badge(&user, &tx_hash);

        // Second redemption with same tx_hash - should fail with TransactionAlreadyRedeemed error
        let result = client.try_redeem_badge(&user, &tx_hash);
        
        assert_eq!(result, Err(Ok(ContractError::TransactionAlreadyRedeemed)));
    }

    #[test]
    fn test_redemption_limit() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &2, // Only 2 redemptions allowed
            &0,
        );

        client.mint_badge(&admin, &user, &1);

        // Redeem twice successfully
        let tx1 = String::from_str(&env, "tx_001");
        client.redeem_badge(&user, &tx1);

        let tx2 = String::from_str(&env, "tx_002");
        client.redeem_badge(&user, &tx2);

        // Third redemption should fail with RedemptionLimitReached error
        let tx3 = String::from_str(&env, "tx_003");
        let result = client.try_redeem_badge(&user, &tx3);
        
        assert_eq!(result, Err(Ok(ContractError::RedemptionLimitReached)));
    }

    #[test]
    fn test_revoke_badge() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());
        client.create_badge_type(&admin, &1, &String::from_str(&env, "Bronze"), &500, &10, &0);
        client.mint_badge(&admin, &user, &1);

        // Badge is active
        let discount = client.get_user_discount(&user);
        assert_eq!(discount, 500);

        // Revoke badge
        client.revoke_badge(&admin, &user);

        // Badge should no longer give discount
        let discount = client.get_user_discount(&user);
        assert_eq!(discount, 0);
    }

    #[test]
    fn test_parameter_proposal_and_execution() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());

        // Propose parameter change
        let parameter_key = symbol_short!("max_rdm");
        let new_value = 20u128;

        let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value);

        // Verify proposal was created
        let proposal = client.get_parameter_proposal(&proposal_id);
        assert_eq!(proposal.parameter_key, parameter_key);
        assert_eq!(proposal.new_value, new_value);
        assert_eq!(proposal.executed, false);
        assert_eq!(proposal.cancelled, false);

        // Try to execute before timelock (should fail)
        let result = client.try_execute_parameter_change(&admin, &proposal_id);
        assert!(result.is_err());

        // Advance time past timelock
        env.ledger().set(soroban_sdk::testutils::LedgerInfo {
            timestamp: env.ledger().timestamp() + 86401,
            protocol_version: 26,
            sequence_number: 20,
            network_id: [0u8; 32],
            base_reserve: 10,
            max_entry_ttl: 6_312_000,
            min_persistent_entry_ttl: 4096,
            min_temp_entry_ttl: 16,
        });

        // Execute parameter change
        client.execute_parameter_change(&admin, &proposal_id);

        // Verify proposal is executed
        let proposal = client.get_parameter_proposal(&proposal_id);
        assert_eq!(proposal.executed, true);
    }

    #[test]
    fn test_parameter_proposal_cancellation() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());

        // Propose parameter change
        let parameter_key = symbol_short!("max_rdm");
        let new_value = 20u128;

        let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value);

        // Cancel proposal
        client.cancel_parameter_proposal(&admin, &proposal_id);

        // Verify proposal is cancelled
        let proposal = client.get_parameter_proposal(&proposal_id);
        assert_eq!(proposal.cancelled, true);

        // Try to execute cancelled proposal (should fail)
        let result = client.try_execute_parameter_change(&admin, &proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_parameter_proposal_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, AcademyRewardsContract);
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let unauthorized = Address::generate(&env);

        client.initialize(&admin, &default_cb_config());

        let parameter_key = symbol_short!("max_rdm");
        let new_value = 20u128;

        // Try to propose parameter change with unauthorized address
        let result = client.try_propose_parameter_change(&unauthorized, &parameter_key, &new_value);
        assert_eq!(result, Err(Ok(ContractError::Unauthorized)));
    }
}