use soroban_sdk::{contracterror, Address, Env, token};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FeeError {
    InsufficientBalance = 1001,
    InvalidAmount = 1002,
}

pub struct FeeManager;

impl FeeManager {
    /// Collects a fee from a payer to a destination.
    /// 
    /// # Arguments
    /// * `env` - The environment
    /// * `token` - The token contract address to pay fees in
    /// * `payer` - The address paying the fee
    /// * `destination` - The address receiving the fee
    /// * `amount` - The amount of fee to pay
    /// 
    /// # Returns
    /// * `Result<(), FeeError>` - Ok if successful, Error otherwise
    pub fn collect_fee(
        env: &Env,
        token: &Address,
        payer: &Address,
        destination: &Address,
        amount: i128,
    ) -> Result<(), FeeError> {
        if amount < 0 {
            return Err(FeeError::InvalidAmount);
        }
        
        if amount == 0 {
            return Ok(());
        }

        let token_client = token::Client::new(env, token);
        
        // Check balance
        let balance = token_client.balance(payer);
        if balance < amount {
            return Err(FeeError::InsufficientBalance);
        }

        // Perform transfer
        // Note: This requires 'payer' to authorize the transaction if not already authorized
        token_client.transfer(payer, destination, &amount);

        Ok(())
    }
}
