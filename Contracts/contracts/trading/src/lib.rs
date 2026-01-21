#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};
use shared::fees::{FeeManager, FeeError};

#[contract]
pub struct TradingContract;

#[contractimpl]
impl TradingContract {
    /// Executes a trade and collects a fee.
    pub fn trade(
        env: Env, 
        trader: Address, 
        fee_token: Address, 
        fee_amount: i128,
        fee_recipient: Address
    ) -> Result<(), FeeError> {
        trader.require_auth();

        // Collect Fee First
        // If this fails (e.g. insufficient balance), it returns FeeError, 
        // and the transaction is gracefully failed (reverted) with that error.
        FeeManager::collect_fee(&env, &fee_token, &trader, &fee_recipient, fee_amount)?;

        // Perform Trade Logic (Placeholder)
        // ...
        
        Ok(())
    }
}

#[cfg(test)]
mod test;
