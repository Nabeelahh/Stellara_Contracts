#![cfg(test)]

use proptest::prelude::*;
use soroban_sdk::{testutils::Address as _, Env, Address, IntoVal};

use token::{TokenContract, TokenContractClient};

#[derive(Clone, Debug)]
enum Action {
    Transfer(i128),
    Mint(i128),
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// -----------------------------------------
    /// Stateful invariant: supply + balances safe
    /// -----------------------------------------
    #[test]
    fn state_machine_invariants(
        initial_supply in 1_000i128..1_000_000i128,
        actions in prop::collection::vec(
            prop_oneof![
                (1i128..10_000i128).prop_map(Action::Transfer),
                (1i128..10_000i128).prop_map(Action::Mint),
            ],
            1..20
        )
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        let contract_id = env.register_contract(None, TokenContract);
        let token = TokenContractClient::new(&env, &contract_id);

        token.initialize(
            &owner,
            &"Stellara Token".into_val(&env),
            &"STLR".into_val(&env),
            &7,
        );
        token.mint(&user1, &initial_supply);

        let mut expected_supply = initial_supply;

        for action in actions {
            match action {
                Action::Transfer(amount) => {
                    let balance = token.balance(&user1);
                    let amt = amount.min(balance);
                    if amt > 0 {
                        token.transfer(&user1, &user2, &amt);
                    }
                }
                Action::Mint(amount) => {
                    token.mint(&user1, &amount);
                    expected_supply += amount;
                }
            }

            // 🔒 invariants after every step
            let total_supply = token.total_supply();
            let b1 = token.balance(&user1);
            let b2 = token.balance(&user2);

            prop_assert_eq!(b1 + b2, total_supply);
            prop_assert!(b1 >= 0);
            prop_assert!(b2 >= 0);
            prop_assert_eq!(total_supply, expected_supply);
        }
    }

    /// -------------------------------
    /// Invariant: totalSupply conserved on transfer
    /// -------------------------------
    #[test]
    fn total_supply_invariant(
        initial_supply in 1_000i128..1_000_000i128,
        transfer_amount in 1i128..10_000i128,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        let contract_id = env.register_contract(None, TokenContract);
        let token = TokenContractClient::new(&env, &contract_id);

        token.initialize(
            &admin,
            &"Stellara Token".into_val(&env),
            &"STLR".into_val(&env),
            &7,
        );
        token.mint(&user1, &initial_supply);

        let supply_before = token.total_supply();

        let amount = transfer_amount.min(initial_supply);
        token.transfer(&user1, &user2, &amount);

        let supply_after = token.total_supply();
        prop_assert_eq!(supply_before, supply_after);
    }

    /// -------------------------------------
    /// Invariant: balances are never negative
    /// -------------------------------------
    #[test]
    fn balances_non_negative(
        supply in 1_000i128..1_000_000i128,
        transfer_amount in 1i128..500_000i128,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);

        let contract_id = env.register_contract(None, TokenContract);
        let token = TokenContractClient::new(&env, &contract_id);

        token.initialize(
            &admin,
            &"Stellara Token".into_val(&env),
            &"STLR".into_val(&env),
            &7,
        );
        token.mint(&user1, &supply);

        let amount = transfer_amount.min(supply);
        token.transfer(&user1, &user2, &amount);

        prop_assert!(token.balance(&user1) >= 0);
        prop_assert!(token.balance(&user2) >= 0);
    }

    /// --------------------------------
    /// Invariant: mint increases total supply
    /// --------------------------------
    #[test]
    fn ownership_invariant(
        _supply in 1_000i128..1_000_000i128,
        mint_amount in 1i128..100_000i128,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let owner = Address::generate(&env);
        let user = Address::generate(&env);

        let contract_id = env.register_contract(None, TokenContract);
        let token = TokenContractClient::new(&env, &contract_id);

        token.initialize(
            &owner,
            &"Stellara Token".into_val(&env),
            &"STLR".into_val(&env),
            &7,
        );

        let before = token.total_supply();
        token.mint(&user, &mint_amount);
        let after = token.total_supply();
        prop_assert_eq!(after, before + mint_amount);
    }
}
