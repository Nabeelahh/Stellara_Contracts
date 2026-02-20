#[cfg(test)]
mod test {
    use crate::{AcademyRewardsContract, AcademyRewardsContractClient, BadgeMetadata, ContractError, DataKey};
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env, String};

    fn setup_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        set_timestamp(&env, 1000);

        let contract_id = env.register_contract(None, AcademyRewardsContract);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        (env, admin, user, contract_id)
    }

    #[test]
    fn test_initialize_and_double_init() {
        let (env, admin, _user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        client.initialize(&admin);

        let result = client.try_initialize(&admin);
        assert_eq!(result, Err(Ok(ContractError::AlreadyInitialized)));

        let _ = env;
    }

    #[test]
    fn test_admin_auth_and_invalid_discount() {
        let (_env, admin, user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&_env, &contract_id);

        client.initialize(&admin);

        let unauthorized = client.try_create_badge_type(
            &user,
            &1,
            &String::from_str(&_env, "Bronze"),
            &500,
            &10,
            &0,
        );
        assert_eq!(unauthorized, Err(Ok(ContractError::Unauthorized)));

        let invalid_discount = client.try_create_badge_type(
            &admin,
            &1,
            &String::from_str(&_env, "Bronze"),
            &10001,
            &10,
            &0,
        );
        assert_eq!(invalid_discount, Err(Ok(ContractError::InvalidDiscount)));
    }

    #[test]
    fn test_mint_badge_errors() {
        let (env, admin, user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        // Not initialized
        let not_init = client.try_mint_badge(&admin, &user, &1);
        assert_eq!(not_init, Err(Ok(ContractError::NotInitialized)));

        client.initialize(&admin);

        // Badge type missing
        let missing_type = client.try_mint_badge(&admin, &user, &1);
        assert_eq!(missing_type, Err(Ok(ContractError::BadgeTypeNotFound)));

        // Create a badge type
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &10,
            &0,
        );

        // Disable badge type by running inside contract context
        env.as_contract(&contract_id, || {
            let metadata = BadgeMetadata {
                name: String::from_str(&env, "Bronze"),
                discount_bps: 500,
                max_redemptions: 10,
                validity_duration: 0,
                enabled: false,
            };
            env.storage()
                .persistent()
                .set(&DataKey::BadgeMetadata(1), &metadata);
        });

        let disabled = client.try_mint_badge(&admin, &user, &1);
        assert_eq!(disabled, Err(Ok(ContractError::BadgeTypeDisabled)));

        // Re-enable and mint
        env.as_contract(&contract_id, || {
            let metadata = BadgeMetadata {
                name: String::from_str(&env, "Bronze"),
                discount_bps: 500,
                max_redemptions: 10,
                validity_duration: 0,
                enabled: true,
            };
            env.storage()
                .persistent()
                .set(&DataKey::BadgeMetadata(1), &metadata);
        });

        client.mint_badge(&admin, &user, &1);

        // Duplicate mint
        let duplicate = client.try_mint_badge(&admin, &user, &1);
        assert_eq!(duplicate, Err(Ok(ContractError::UserAlreadyHasBadge)));

        // Paused prevents mint
        client.set_paused(&admin, &true);
        let paused = client.try_mint_badge(&admin, &user, &1);
        assert_eq!(paused, Err(Ok(ContractError::ContractPaused)));

        // Ensure badge stored
        let badge = client.get_user_badge(&user).unwrap();
        assert_eq!(badge.badge_type, 1);
        assert_eq!(badge.discount_bps, 500);
        assert_eq!(badge.redeemed_count, 0);
    }

    #[test]
    fn test_redeem_badge_errors_and_history() {
        let (env, admin, user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        client.initialize(&admin);
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &1,
            &10,
        );

        // No badge
        let no_badge = client.try_redeem_badge(&user, &String::from_str(&env, "tx_0"));
        assert_eq!(no_badge, Err(Ok(ContractError::UserHasNoBadge)));

        client.mint_badge(&admin, &user, &1);

        // Expired
        set_timestamp(&env, 1000 + 20);
        let expired = client.try_redeem_badge(&user, &String::from_str(&env, "tx_1"));
        assert_eq!(expired, Err(Ok(ContractError::BadgeExpired)));

        // Reset time before expiry and redeem
        set_timestamp(&env, 1000 + 5);
        let tx_hash = String::from_str(&env, "tx_2");
        let discount = client.redeem_badge(&user, &tx_hash);
        assert_eq!(discount, 500);

        // Redemption history
        let history = client.get_redemption_history(&user, &0).unwrap();
        assert_eq!(history.badge_type, 1);
        assert_eq!(history.discount_applied, 500);

        // Transaction reuse
        let reused = client.try_redeem_badge(&user, &tx_hash);
        assert_eq!(reused, Err(Ok(ContractError::TransactionAlreadyRedeemed)));

        // Limit reached
        let limit = client.try_redeem_badge(&user, &String::from_str(&env, "tx_3"));
        assert_eq!(limit, Err(Ok(ContractError::RedemptionLimitReached)));
    }

    #[test]
    fn test_revoke_and_discount_behavior() {
        let (env, admin, user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        client.initialize(&admin);
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &2,
            &0,
        );
        client.mint_badge(&admin, &user, &1);

        assert_eq!(client.get_user_discount(&user), 500);

        client.revoke_badge(&admin, &user);
        assert_eq!(client.get_user_discount(&user), 0);

        let revoked = client.try_redeem_badge(&user, &String::from_str(&env, "tx_4"));
        assert_eq!(revoked, Err(Ok(ContractError::BadgeNotActive)));

        let missing = client.try_revoke_badge(&admin, &Address::generate(&env));
        assert_eq!(missing, Err(Ok(ContractError::UserHasNoBadge)));
    }

    #[test]
    fn test_getters_and_paused_state() {
        let (env, admin, user, contract_id) = setup_env();
        let client = AcademyRewardsContractClient::new(&env, &contract_id);

        client.initialize(&admin);
        client.create_badge_type(
            &admin,
            &1,
            &String::from_str(&env, "Bronze"),
            &500,
            &1,
            &0,
        );
        client.mint_badge(&admin, &user, &1);

        let meta = client.get_badge_metadata(&1).unwrap();
        assert_eq!(meta.discount_bps, 500);

        let total = client.get_total_minted(&1);
        assert_eq!(total, 1);

        client.set_paused(&admin, &true);
        let paused_redeem = client.try_redeem_badge(&user, &String::from_str(&env, "tx_5"));
        assert_eq!(paused_redeem, Err(Ok(ContractError::ContractPaused)));

        let non_admin = Address::generate(&env);
        let pause_err = client.try_set_paused(&non_admin, &false);
        assert_eq!(pause_err, Err(Ok(ContractError::Unauthorized)));
    }

    fn set_timestamp(env: &Env, timestamp: u64) {
        let mut ledger_info = env.ledger().get();
        ledger_info.timestamp = timestamp;
        env.ledger().set(ledger_info);
    }
}
