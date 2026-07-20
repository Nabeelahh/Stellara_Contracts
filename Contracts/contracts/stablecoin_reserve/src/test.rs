#[cfg(test)]
mod tests {
    use crate::{
        AssetType, RedemptionRequest, RedemptionStatus, ReserveAsset, ReserveError,
        ReserveSnapshot, StablecoinReserveContract,
    };
    use soroban_sdk::{symbol_short, Address, BytesN, Env};

    fn create_test_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env
    }

    fn create_test_addresses(env: &Env) -> (Address, Address, Address, Address) {
        let admin = Address::generate(env);
        let approver1 = Address::generate(env);
        let approver2 = Address::generate(env);
        let executor = Address::generate(env);
        (admin, approver1, approver2, executor)
    }

    #[test]
    fn test_initialize() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        // Verify initialization
        assert_eq!(client.get_reserve_ratio(), Ok(10000)); // 100%
        assert_eq!(client.get_total_reserves(), Ok(0));
    }

    #[test]
    fn test_add_reserve_asset() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add USD reserve
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &1_000_000_000_000u128, // $1M
            &custodian,
            &verification_hash,
        );

        // Verify reserves updated
        assert_eq!(client.get_total_reserves(), Ok(1_000_000_000_000u128));
    }

    #[test]
    fn test_add_reserve_asset_unauthorized() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let unauthorized = Address::generate(&env);
        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Try to add asset with unauthorized address
        let result = client.try_add_reserve_asset(
            &unauthorized,
            &AssetType::USD,
            &1_000_000_000_000u128,
            &custodian,
            &verification_hash,
        );

        assert_eq!(result, Err(Ok(ReserveError::Unauthorized)));
    }

    #[test]
    fn test_generate_proof_of_reserves() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add some reserves
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &1_000_000_000_000u128,
            &custodian,
            &verification_hash,
        );

        // Generate proof of reserves
        let merkle_root = client.generate_proof_of_reserves(&admin);
        assert!(merkle_root.is_ok());
    }

    #[test]
    fn test_rebalancing_needed() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add USD reserves (should be 40% target)
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &1_000_000_000_000u128,
            &custodian,
            &verification_hash,
        );

        // Check if rebalancing is needed (should be false, 100% USD vs 40% target)
        let rebalancing_needed = client.check_rebalancing_needed();
        assert!(rebalancing_needed.is_ok());
        assert!(rebalancing_needed.unwrap()); // Should be true due to large deviation
    }

    #[test]
    fn test_redemption_request() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add sufficient reserves
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &10_000_000_000_000u128, // $10M
            &custodian,
            &verification_hash,
        );

        let large_holder = Address::generate(&env);

        // Request redemption ($1M)
        let request_id = client.request_redemption(&large_holder, &1_000_000_000_000u128);
        assert!(request_id.is_ok());

        // Check request status
        let request = client.get_redemption_status(&request_id.unwrap());
        assert!(request.is_ok());
        assert_eq!(request.unwrap().status, RedemptionStatus::Pending);
    }

    #[test]
    fn test_redemption_request_insufficient_amount() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let small_holder = Address::generate(&env);

        // Request redemption with amount less than $1M
        let result = client.try_request_redemption(&small_holder, &500_000_000_000u128); // $500K
        assert_eq!(result, Err(Ok(ReserveError::RedemptionAmountTooSmall)));
    }

    #[test]
    fn test_regulatory_report() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add reserves
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &1_000_000_000_000u128,
            &custodian,
            &verification_hash,
        );

        // Generate regulatory report
        let report_id = client.generate_regulatory_report(&admin);
        assert!(report_id.is_ok());
    }

    #[test]
    fn test_custodian_registration() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let name = symbol_short!("TestCustodian");
        let api_endpoint = symbol_short!("https://api.test.com");

        // Register custodian
        client.register_custodian(
            &admin,
            &custodian,
            &name,
            &api_endpoint,
            &VerificationMethod::API,
        );

        // Verify registration
        let custodian_info = client.get_custodian_info(&custodian);
        assert!(custodian_info.is_ok());
    }

    #[test]
    fn test_reserve_snapshot() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let custodian = Address::generate(&env);
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        // Add reserves
        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &1_000_000_000_000u128,
            &custodian,
            &verification_hash,
        );

        // Get snapshot
        let snapshot = client.get_reserve_snapshot();
        assert!(snapshot.is_ok());

        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.total_reserves, 1_000_000_000_000u128);
        assert_eq!(snapshot.reserve_ratio, 10000); // 100%
        assert_eq!(snapshot.assets.len(), 1);
    }

    #[test]
    fn test_governance_upgrade_proposal() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let new_contract_hash = BytesN::from_array(&env, &[2u8; 32]);
        let description = symbol_short!("Test upgrade");
        let approval_threshold = 2u32;
        let timelock_delay = 3600u64;

        // Propose upgrade
        let proposal_id = client.propose_upgrade(
            &admin,
            &new_contract_hash,
            &description,
            &approvers,
            &approval_threshold,
            &timelock_delay,
        );

        assert!(proposal_id.is_ok());
    }

    #[test]
    fn test_parameter_proposal_and_execution() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        // Propose parameter change
        let parameter_key = symbol_short!("rebal_thresh");
        let new_value = 750u128; // 7.5%

        let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value);
        assert!(proposal_id.is_ok());

        let proposal_id = proposal_id.unwrap();

        // Verify proposal was created
        let proposal = client.get_parameter_proposal(&proposal_id);
        assert!(proposal.is_ok());

        let proposal = proposal.unwrap();
        assert_eq!(proposal.parameter_key, parameter_key);
        assert_eq!(proposal.new_value, new_value);
        assert_eq!(proposal.executed, false);
        assert_eq!(proposal.cancelled, false);

        // Try to execute before timelock (should fail)
        let result = client.try_execute_parameter_change(&executor, &proposal_id);
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
        let result = client.execute_parameter_change(&executor, &proposal_id);
        assert!(result.is_ok());

        // Verify proposal is executed
        let proposal = client.get_parameter_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.executed, true);
    }

    #[test]
    fn test_parameter_proposal_cancellation() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        // Propose parameter change
        let parameter_key = symbol_short!("rebal_thresh");
        let new_value = 750u128;

        let proposal_id = client.propose_parameter_change(&admin, &parameter_key, &new_value).unwrap();

        // Cancel proposal
        let result = client.cancel_parameter_proposal(&admin, &proposal_id);
        assert!(result.is_ok());

        // Verify proposal is cancelled
        let proposal = client.get_parameter_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.cancelled, true);

        // Try to execute cancelled proposal (should fail)
        let result = client.try_execute_parameter_change(&executor, &proposal_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_parameter_proposal_unauthorized() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        let unauthorized = Address::generate(&env);
        let parameter_key = symbol_short!("rebal_thresh");
        let new_value = 750u128;

        // Try to propose parameter change with unauthorized address
        let result = client.try_propose_parameter_change(&unauthorized, &parameter_key, &new_value);
        assert_eq!(result, Err(Ok(ReserveError::Unauthorized)));
    }

    #[test]
    fn test_comprehensive_workflow() {
        let env = create_test_env();
        let contract_id = env.register_contract(None, StablecoinReserveContract);
        let client = StablecoinReserveContractClient::new(&env, &contract_id);

        let (admin, approver1, approver2, executor) = create_test_addresses(&env);
        let stablecoin_address = Address::generate(&env);
        let approvers = vec![&env, approver1.clone(), approver2.clone()];

        // Initialize system
        client.initialize(&admin, &approvers, &executor, &stablecoin_address);

        // Register custodians
        let custodian1 = Address::generate(&env);
        let custodian2 = Address::generate(&env);

        client.register_custodian(
            &admin,
            &custodian1,
            &symbol_short!("Coinbase"),
            &symbol_short!("https://api.coinbase.com"),
            &VerificationMethod::API,
        );

        client.register_custodian(
            &admin,
            &custodian2,
            &symbol_short!("BitGo"),
            &symbol_short!("https://api.bitgo.com"),
            &VerificationMethod::API,
        );

        // Add diverse reserve assets
        let verification_hash = BytesN::from_array(&env, &[1u8; 32]);

        client.add_reserve_asset(
            &admin,
            &AssetType::USD,
            &4_000_000_000_000u128, // $4M (40%)
            &custodian1,
            &verification_hash,
        );

        client.add_reserve_asset(
            &admin,
            &AssetType::Treasury,
            &3_000_000_000_000u128, // $3M (30%)
            &custodian1,
            &verification_hash,
        );

        client.add_reserve_asset(
            &admin,
            &AssetType::Repo,
            &2_000_000_000_000u128, // $2M (20%)
            &custodian2,
            &verification_hash,
        );

        client.add_reserve_asset(
            &admin,
            &AssetType::CorporateBond,
            &1_000_000_000_000u128, // $1M (10%)
            &custodian2,
            &verification_hash,
        );

        // Verify total reserves
        assert_eq!(client.get_total_reserves(), Ok(10_000_000_000_000u128));

        // Generate proof of reserves
        let merkle_root = client.generate_proof_of_reserves(&admin);
        assert!(merkle_root.is_ok());

        // Check rebalancing (should not be needed with proper allocation)
        let rebalancing_needed = client.check_rebalancing_needed();
        assert!(rebalancing_needed.is_ok());
        assert!(!rebalancing_needed.unwrap());

        // Process large holder redemption
        let large_holder = Address::generate(&env);
        let request_id = client.request_redemption(&large_holder, &1_000_000_000_000u128);
        assert!(request_id.is_ok());

        // Approve redemption
        client.approve_redemption(&admin, &request_id.unwrap());

        // Process redemption
        client.process_redemption(&executor, &request_id.unwrap());

        // Verify reserves decreased
        assert_eq!(client.get_total_reserves(), Ok(9_000_000_000_000u128));

        // Generate regulatory report
        let report_id = client.generate_regulatory_report(&admin);
        assert!(report_id.is_ok());

        // Sync with custodians
        client.sync_with_custodian(&admin, &custodian1);
        client.sync_with_custodian(&admin, &custodian2);

        // Verify final state
        let snapshot = client.get_reserve_snapshot();
        assert!(snapshot.is_ok());

        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.total_reserves, 9_000_000_000_000u128);
        assert_eq!(snapshot.assets.len(), 4);
    }
}
