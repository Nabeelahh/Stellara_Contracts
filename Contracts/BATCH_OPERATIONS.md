# Batch Operations Documentation

## Overview

Batch operations allow multiple transactions to be processed in a single call, significantly reducing gas costs and improving user experience. This feature has been implemented across all three core contracts in the Stellara ecosystem.

## Benefits

- **Gas Savings**: Reduce transaction costs by batching multiple operations
- **Atomic Execution**: Ensure all operations in a batch succeed or fail together
- **Improved UX**: Users can perform multiple actions in a single transaction
- **Partial Failure Handling**: Individual operations can fail without affecting the entire batch

## Contracts with Batch Operations

### 1. Trading Contract (`UpgradeableTradingContract`)

#### Batch Trading

**Function**: `batch_trade(requests: Vec<BatchTradeRequest>) -> BatchTradeOperation`

**Request Structure**:
```rust
pub struct BatchTradeRequest {
    pub trader: Address,
    pub pair: Symbol,
    pub amount: i128,
    pub price: i128,
    pub is_buy: bool,
    pub fee_token: Address,
    pub fee_amount: i128,
    pub fee_recipient: Address,
}
```

**Response Structure**:
```rust
pub struct BatchTradeOperation {
    pub successful_trades: Vec<u64>,
    pub failed_trades: Vec<BatchTradeResult>,
    pub total_fees_collected: i128,
    pub gas_saved: i128,
}
```

**Batch Size Limit**: 50 trades per batch

**Example Usage**:
```javascript
const requests = [
    {
        trader: "GD...",
        pair: "XLMUSDC",
        amount: 100,
        price: 10,
        is_buy: true,
        fee_token: "GB...",
        fee_amount: 5,
        fee_recipient: "GD..."
    },
    {
        trader: "GD...",
        pair: "XLMUSDC",
        amount: 200,
        price: 11,
        is_buy: false,
        fee_token: "GB...",
        fee_amount: 10,
        fee_recipient: "GD..."
    }
];

const result = await contract.call("batch_trade", [requests]);
console.log(`Successful trades: ${result.successful_trades.length}`);
console.log(`Gas saved: ${result.gas_saved}`);
```

### 2. Academy Vesting Contract (`AcademyVestingContract`)

#### Batch Vesting Grants

**Function**: `batch_grant_vesting(admin: Address, requests: Vec<BatchVestingRequest>) -> BatchVestingOperation`

**Request Structure**:
```rust
pub struct BatchVestingRequest {
    pub beneficiary: Address,
    pub amount: i128,
    pub start_time: u64,
    pub cliff: u64,
    pub duration: u64,
}
```

**Response Structure**:
```rust
pub struct BatchVestingOperation {
    pub successful_grants: Vec<u64>,
    pub failed_grants: Vec<BatchVestingResult>,
    pub total_amount_granted: i128,
    pub gas_saved: i128,
}
```

**Batch Size Limit**: 25 grants per batch

#### Batch Claims

**Function**: `batch_claim(requests: Vec<BatchClaimRequest>) -> Vec<BatchClaimResult>`

**Request Structure**:
```rust
pub struct BatchClaimRequest {
    pub grant_id: u64,
    pub beneficiary: Address,
}
```

**Response Structure**:
```rust
pub struct BatchClaimResult {
    pub grant_id: u64,
    pub amount_claimed: Option<i128>,
    pub success: bool,
    pub error_code: Option<u32>,
}
```

**Batch Size Limit**: 20 claims per batch

**Example Usage**:
```javascript
// Batch grant vesting
const grantRequests = [
    {
        beneficiary: "GD...",
        amount: 1000,
        start_time: 1640995200, // Jan 1, 2022
        cliff: 86400,           // 1 day
        duration: 31536000      // 1 year
    },
    {
        beneficiary: "GD...",
        amount: 2000,
        start_time: 1640995200,
        cliff: 172800,          // 2 days
        duration: 63072000      // 2 years
    }
];

const grantResult = await contract.call("batch_grant_vesting", [admin, grantRequests]);

// Batch claim
const claimRequests = [
    { grant_id: 1, beneficiary: "GD..." },
    { grant_id: 2, beneficiary: "GD..." }
];

const claimResults = await contract.call("batch_claim", [claimRequests]);
```

### 3. Social Rewards Contract (`SocialRewardsContract`)

#### Batch Reward Addition

**Function**: `batch_add_reward(admin: Address, requests: Vec<BatchRewardRequest>) -> BatchRewardOperation`

**Request Structure**:
```rust
pub struct BatchRewardRequest {
    pub user: Address,
    pub amount: i128,
    pub reward_type: Symbol,
    pub reason: Symbol,
}
```

**Response Structure**:
```rust
pub struct BatchRewardOperation {
    pub successful_rewards: Vec<u64>,
    pub failed_rewards: Vec<BatchRewardResult>,
    pub total_amount_granted: i128,
    pub gas_saved: i128,
}
```

**Batch Size Limit**: 30 rewards per batch

#### Batch Reward Claims

**Function**: `batch_claim_reward(requests: Vec<BatchRewardClaimRequest>) -> Vec<BatchRewardClaimResult>`

**Request Structure**:
```rust
pub struct BatchRewardClaimRequest {
    pub reward_id: u64,
    pub user: Address,
}
```

**Response Structure**:
```rust
pub struct BatchRewardClaimResult {
    pub reward_id: u64,
    pub amount_claimed: Option<i128>,
    pub success: bool,
    pub error_code: Option<u32>,
}
```

**Batch Size Limit**: 25 claims per batch

**Example Usage**:
```javascript
// Batch add rewards
const rewardRequests = [
    {
        user: "GD...",
        amount: 100,
        reward_type: "referral",
        reason: "invited_new_user"
    },
    {
        user: "GD...",
        amount: 50,
        reward_type: "engagement",
        reason: "daily_login"
    }
];

const rewardResult = await contract.call("batch_add_reward", [admin, rewardRequests]);

// Batch claim rewards
const claimRequests = [
    { reward_id: 1, user: "GD..." },
    { reward_id: 2, user: "GD..." }
];

const claimResults = await contract.call("batch_claim_reward", [claimRequests]);
```

## Error Handling

### Common Error Types

1. **BatchSizeExceeded**: When the batch exceeds the maximum allowed size
2. **BatchOperationFailed**: General batch operation failure
3. **ContractPaused**: When the contract is paused (trading only)
4. **Unauthorized**: When the caller lacks required permissions
5. **InvalidAmount**: When amounts are invalid (negative, zero, etc.)

### Partial Failure Handling

Batch operations are designed to handle partial failures gracefully:

- **Successful Operations**: Continue processing even if some operations fail
- **Detailed Results**: Each operation returns individual success/failure status
- **Error Codes**: Failed operations include specific error codes for debugging
- **Atomic State Updates**: Successful operations are committed, failed ones are skipped

### Error Response Example

```javascript
// Example of partial failure response
{
    successful_trades: [1, 3],      // Trade IDs that succeeded
    failed_trades: [
        {
            trade_id: null,
            success: false,
            error_code: 3002        // InvalidAmount error
        },
        {
            trade_id: null,
            success: false,
            error_code: 3005        // InsufficientBalance error
        }
    ],
    total_fees_collected: 150,
    gas_saved: 2000
}
```

## Gas Optimization

### Estimated Gas Savings

- **Trading**: ~1000 gas units saved per trade
- **Vesting Grants**: ~800 gas units saved per grant
- **Vesting Claims**: ~600 gas units saved per claim
- **Reward Addition**: ~500 gas units saved per reward
- **Reward Claims**: ~400 gas units saved per claim

### Optimization Techniques

1. **Bulk Storage Operations**: Minimize storage reads/writes
2. **Shared Token Client**: Reuse token client instances
3. **Batch Validation**: Validate all requests before processing
4. **Efficient Event Emission**: Minimize event overhead

## Security Considerations

### Authentication

- Each operation in a batch requires proper authentication
- Admin-only operations verify admin permissions
- User operations verify user ownership

### Resource Limits

- **Batch Size Limits**: Prevent resource exhaustion attacks
- **Gas Limits**: Built-in protection against gas exhaustion
- **Memory Management**: Efficient memory usage for large batches

### Reentrancy Protection

- Batch operations maintain the same reentrancy protection as individual operations
- State updates are atomic and consistent

## Best Practices

### For Developers

1. **Validate Input**: Validate all batch inputs before sending
2. **Handle Partial Failures**: Always check individual operation results
3. **Monitor Gas Usage**: Track gas consumption for optimization
4. **Use Appropriate Batch Sizes**: Stay within recommended limits

### For Users

1. **Group Similar Operations**: Batch operations of the same type
2. **Check Results**: Review individual operation results
3. **Plan Batches**: Break large operations into multiple smaller batches
4. **Monitor Gas Costs**: Compare batch vs individual operation costs

## Testing

Comprehensive test suites have been implemented for all batch operations:

- **Happy Path Tests**: Verify successful batch execution
- **Size Limit Tests**: Ensure batch size limits are enforced
- **Partial Failure Tests**: Verify graceful handling of failures
- **Error Handling Tests**: Test all error conditions
- **Event Emission Tests**: Verify proper event generation

Run tests with:
```bash
cargo test --all
```

## Migration Guide

### From Individual Operations

To migrate from individual operations to batch operations:

1. **Collect Operations**: Group individual operations into arrays
2. **Create Batch Requests**: Convert to batch request format
3. **Handle Results**: Process batch results instead of individual results
4. **Update Error Handling**: Adapt to batch error format

### Example Migration

**Before (Individual Operations)**:
```javascript
const trade1 = await contract.trade(trader1, "XLMUSDC", 100, 10, true, token, 5, recipient);
const trade2 = await contract.trade(trader2, "XLMUSDC", 200, 11, false, token, 10, recipient);
```

**After (Batch Operations)**:
```javascript
const requests = [
    { trader: trader1, pair: "XLMUSDC", amount: 100, price: 10, is_buy: true, fee_token: token, fee_amount: 5, fee_recipient: recipient },
    { trader: trader2, pair: "XLMUSDC", amount: 200, price: 11, is_buy: false, fee_token: token, fee_amount: 10, fee_recipient: recipient }
];
const result = await contract.batch_trade(requests);
```

## Future Enhancements

Potential future improvements to batch operations:

1. **Cross-Contract Batching**: Enable operations across multiple contracts
2. **Conditional Batching**: Add conditional logic within batches
3. **Priority Queuing**: Implement priority-based batch processing
4. **Dynamic Batch Sizing**: Adaptive batch size limits based on network conditions
5. **Batch Templates**: Reusable batch operation templates

## Support

For questions or issues regarding batch operations:

1. **Documentation**: Refer to this guide and contract documentation
2. **Test Examples**: Review test files for practical examples
3. **Community**: Engage with the Stellara developer community
4. **Issues**: Report bugs or feature requests on GitHub

---

**Last Updated**: February 20, 2026
**Version**: 1.0
**Status**: Production Ready
