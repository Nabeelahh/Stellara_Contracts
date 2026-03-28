# Liquidity Mining Program 🚀

A comprehensive liquidity mining incentive system that rewards users for providing liquidity to trading pairs with token emissions, time-locked bonus multipliers, governance rights, and APY displays.

## 📋 Overview

The Liquidity Mining Program enables decentralized liquidity providers (LPs) to earn rewards while helping support trading pair depth. The system features:

- **Multi-Pair Support**: Manage rewards across different trading pairs independently
- **Dynamic Reward Calculation**: Per-block emissions with accumulation
- **Bonus Multipliers**: 2x-5x rewards for long-term liquidity provision (30-180 days)
- **Governance Integration**: Lock rewards to gain governance power and voting rights
- **APR/APY Display**: Real-time profitability metrics
- **Event Tracking**: Complete audit trail of all liquidity and reward activities

## 🏗️ Architecture

### Smart Contract (Soroban)
**Location**: `Contracts/contracts/liquidity-mining/`

Core on-chain contract handling:
- Pair management and configuration
- LP token tracking and balance management
- Reward calculation and distribution
- Governance power accumulation
- Event emission for indexing

### Backend Service (NestJS + Prisma)
**Location**: `Backend/src/liquidity-mining/`

Off-chain services for:
- LP balance history tracking
- Reward calculations and caching
- User statistics aggregation
- APR/APY computations
- Event logging and analytics

### Database Schema (PostgreSQL)
**Location**: `Backend/prisma/schema.prisma`

5 core models:
- `LiquidityMiningPair`: Trading pair configuration
- `LPStake`: User LP provision records
- `LiquidityReward`: Claimed reward history
- `GovernanceLock`: Locked governance tokens
- `LiquidityMiningEvent`: Event audit log

## 📊 Data Models

### LiquidityMiningPair
```typescript
{
  id: string;                          // UUID
  pairId: number;                      // Unique pair identifier
  pairSymbol: string;                  // "USDC_STELLAR"
  emissionsPerBlock: Decimal;          // Reward tokens per block
  totalAllocated: Decimal;             // Total rewards for this pair
  accumulatedRewardPerShare: Decimal;  // For reward distribution
  lastUpdateBlock: BigInt;             // Block height of last update
  active: boolean;                     // Enable/disable liquidity mining
}
```

### LPStake
```typescript
{
  id: string;
  userAddress: string;                 // User wallet
  pairId: number;                      // Which pair
  lpBalance: Decimal;                  // Amount of LP tokens staked
  startTimestamp: DateTime;            // When liquidity started
  rewardDebt: Decimal;                 // Claimed rewards tracking
  bonusMultiplierTier: number;         // 0=1x, 1=2x, 2=3x, 3=5x
  lockedUntil: DateTime;               // Lockup expiration
}
```

### LiquidityReward
```typescript
{
  id: string;
  userAddress: string;
  pairId: number;
  rewardAmount: Decimal;               // Base reward
  bonusMultiplier: Decimal;            // Applied multiplier
  finalRewardAmount: Decimal;          // After multiplier
  claimedAt: DateTime;
  transactionHash: string;             // On-chain proof
  blockNumber: BigInt;
}
```

### GovernanceLock
```typescript
{
  id: string;
  userAddress: string;
  lpStakeId: string;                   // Reference to LP stake
  governancePower: Decimal;            // 50% of claimed reward
  lockupDuration: number;              // Days locked (1-365)
  lockedUntil: DateTime;               // When unlocks
  released: boolean;
  releasedAt: DateTime;
}
```

## 💰 Reward Mechanics

### Emission Schedule
- **Base Rate**: Configurable tokens per block per pair
- **Halving** (optional): Reduce emissions at specific block intervals
- **Total Allocation**: Cap on total rewards per pair

### Reward Calculation

```
base_reward = (user_lp_share / total_lp) × emissions_per_block × blocks_elapsed
final_reward = base_reward × (multiplier / 100)
pending_reward = final_reward - claimed_debt
```

### Bonus Multiplier Tiers

Lock liquidity to earn multipliers:

| Tier | Lockup Period | Multiplier | APY Boost |
|------|--------------|-----------|-----------|
| None | None | 1x | 0% |
| 1 | 30 days | 2x | +100% |
| 2 | 90 days | 3x | +200% |
| 3 | 180 days | 5x | +400% |

#### Example
- Provide 1000 USDC-LP with Tier 3 (5x) multiplier
- Base APR: 20%
- With multiplier: 20% × 5 = **100% APR**

### Governance Power

When claiming rewards:
- **50%** distributed as reward tokens
- **50%** locked as governance power

```typescript
governance_power = final_reward_amount / 2
locked_until = now + lockup_days
```

Governance tokens provide:
- Voting rights in protocol governance
- Access to governance DAO
- Proportional allocation in future airdrops

## 🔄 Workflow

### User: Provide Liquidity

```bash
POST /liquidity-mining/liquidity/provide
{
  "userAddress": "GXXXXX...",
  "pairId": 1,
  "lpAmount": "1000.00",
  "bonusMultiplierTier": 3                    # Optional: 30/90/180 days
}
```

**Response**:
```json
{
  "id": "uuid",
  "userAddress": "GXXXXX...",
  "pairId": 1,
  "lpBalance": "1000.00",
  "startTimestamp": "2026-03-27T10:00:00Z",
  "bonusMultiplierTier": 3,
  "lockedUntil": "2026-09-23T10:00:00Z"      # 180 days from now
}
```

### User: Check Pending Rewards

```bash
GET /liquidity-mining/rewards/pending/:userAddress/:pairId
```

**Response**:
```json
{
  "userAddress": "GXXXXX...",
  "pairId": 1,
  "pendingRewardAmount": "245.67",
  "bonusMultiplier": "5.00",                 # 5x multiplier
  "estimatedFinalAmount": "245.67",
  "lastClaimTime": "2026-03-20T15:30:00Z"
}
```

### User: Claim Rewards

```bash
POST /liquidity-mining/rewards/claim
{
  "userAddress": "GXXXXX...",
  "pairId": 1
}
```

**Response**:
```json
{
  "id": "uuid",
  "userAddress": "GXXXXX...",
  "pairId": 1,
  "rewardAmount": "245.67",
  "bonusMultiplier": "5.00",
  "finalRewardAmount": "245.67",
  "claimedAt": "2026-03-27T20:15:00Z"
}
```

### User: Lock for Governance

```bash
POST /liquidity-mining/rewards/lock-governance
{
  "userAddress": "GXXXXX...",
  "pairId": 1,
  "lockupDays": 90
}
```

**Response**:
```json
{
  "id": "uuid",
  "userAddress": "GXXXXX...",
  "governancePower": "122.83",               # 50% of claimed
  "lockupDuration": 90,
  "lockedUntil": "2026-06-25T20:15:00Z",
  "released": false
}
```

### Admin: Create Mining Pair

```bash
POST /liquidity-mining/pairs
{
  "pairId": 1,
  "pairSymbol": "USDC_STELLAR",
  "emissionsPerBlock": "100.00",
  "totalAllocated": "1000000.00"
}
```

### User: View Statistics

```bash
GET /liquidity-mining/user/:userAddress/statistics
```

**Response**:
```json
{
  "userAddress": "GXXXXX...",
  "totalLpProvided": "5000.00",              # All pairs combined
  "totalRewardsClaimed": "1245.89",
  "governancePower": "612.45",               # Unlocked governance
  "activeStakes": [...],                     # Array of LPStakeResponseDto
  "recentRewards": [...],                    # Last 10 claims
  "governanceLocks": [...]                   # Active + released locks
}
```

### View Pair Statistics

```bash
GET /liquidity-mining/pairs/:pairId/statistics
```

**Response**:
```json
{
  "pairId": 1,
  "pairSymbol": "USDC_STELLAR",
  "totalLiquidityStaked": "500000.00",
  "emissionsPerBlock": "100.00",
  "aprPercentage": "52.30",
  "apyPercentage": "67.89",                  # With daily compounding
  "totalStakers": 234,
  "averageLockupTier": 1.8,                  # Average multiplier tier
  "active": true
}
```

## 📡 API Endpoints

### Pair Management
- `POST /liquidity-mining/pairs` - Create new mining pair
- `GET /liquidity-mining/pairs` - List all pairs
- `GET /liquidity-mining/pairs/:pairId` - Get pair details
- `GET /liquidity-mining/pairs/:pairId/statistics` - Get pair stats

### Liquidity Provision
- `POST /liquidity-mining/liquidity/provide` - Add liquidity
- `POST /liquidity-mining/liquidity/withdraw` - Remove liquidity
- `GET /liquidity-mining/liquidity/:userAddress/:pairId` - Get LP stake

### Rewards
- `GET /liquidity-mining/rewards/pending/:userAddress/:pairId` - Pending rewards
- `POST /liquidity-mining/rewards/claim` - Claim accumulated rewards
- `POST /liquidity-mining/rewards/lock-governance` - Lock 50% for governance

### Analytics
- `GET /liquidity-mining/user/:userAddress/statistics` - User stats
- `GET /liquidity-mining/health` - Health check

## 🔍 APR/APY Calculation

### Annual Percentage Rate (APR)
```
APR = (Annual Emissions / Total Liquidity Staked) × 100
Annual Emissions = Emissions Per Block × 6500 blocks/day × 365 days
```

### Annual Percentage Yield (APY)
```
APY = (1 + (APR / 365))^365 - 1
This accounts for daily compounding of rewards
```

### Example Calculation
- Pair: USDC_STELLAR
- Emissions: 100 tokens/block
- Total Liquidity: 500,000 LP tokens
- Daily blocks: 6,500

```
Annual Emissions = 100 × 6500 × 365 = 237,250,000 tokens
APR = (237,250,000 / 500,000) × 100 = 47,450%
APY = (1 + (47450/365))^365 - 1 ≈ ???% (compounded daily)
```

## 🔐 Security Considerations

### Lockup Enforcement
- Contract prevents withdrawal before lockup period expires
- On-chain timestamp validation
- Automatic reward claiming on forced withdrawal

### Bonus Multiplier Integrity
- Multipliers stored on-chain
- Cannot be changed retroactively for existing stakes
- Time-locked validation

### Decimal Precision
- 4 decimal places for token amounts (Decimal type)
- 5 decimal places for percentages
- BigInt for block heights to prevent overflow

### Event Auditing
- All transactions logged to `LiquidityMiningEvent` table
- Complete audit trail for compliance
- Event types: provide_liquidity, withdraw_liquidity, claim_reward, lock_governance

## 📝 Example Scenarios

### Scenario 1: Conservative LP (1x multiplier)
1. Provide 1000 USDC-LP to USDC_STELLAR pair
2. No lockup, standard 1x multiplier
3. Daily rewards compounding
4. Claim anytime without penalty
5. Use case: High liquidity, flexible capital

### Scenario 2: Aggressive LP (5x multiplier)
1. Provide 1000 USDC-LP with 180-day lockup
2. Bonus 5x multiplier applied
3. Earn 5x more rewards for 6 months
4. After 180 days, can withdraw anytime
5. Lock governance power to participate in DAO
6. Use case: Long-term commitment, governance participation

### Scenario 3: Governance Power Accumulation
1. Provide liquidity over multiple pairs
2. Claim rewards monthly to accumulate governance tokens
3. Lock 50% of claims for 90 days
4. Build governance power for voting on:
   - Emission rate changes
   - New trading pair additions
   - Protocol fee adjustments
5. Participate in governance DAO

## 🚀 Deployment

### Prerequisites
- Stellar testnet account with SOL for gas
- Soroban CLI v20.5+
- Node.js 18+
- PostgreSQL 14+

### Contract Deployment
```bash
cd Contracts/contracts/liquidity-mining
cargo build --release --target wasm32-unknown-unknown

# Build WASM
soroban contract build

# Deploy to testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/stellara_liquidity_mining.wasm \
  --network testnet \
  --source-account <YOUR_ACCOUNT>
```

### Backend Deployment
```bash
cd Backend

# Install dependencies
pnpm install

# Run migrations
npx prisma migrate deploy

# Start server
pnpm start
```

## 📊 Monitoring & Analytics

### Key Metrics to Track
- Total value locked (TVL) per pair
- Average APR/APY over time
- Reward distribution efficiency
- Governance power concentration
- Active staker count and churn rate

### Database Queries

**Total liquidity staked per pair**:
```sql
SELECT pairId, SUM(lpBalance) as totalStaked
FROM lp_stakes
WHERE lpBalance > 0
GROUP BY pairId;
```

**Top stakers by governance power**:
```sql
SELECT userAddress, SUM(governancePower) as totalPower
FROM governance_locks
WHERE released = false
GROUP BY userAddress
ORDER BY totalPower DESC
LIMIT 10;
```

**Reward distribution audit**:
```sql
SELECT 
  pairId, 
  SUM(finalRewardAmount) as totalRewards,
  COUNT(*) as claimCount,
  AVG(bonusMultiplier) as avgMultiplier
FROM liquidity_rewards
GROUP BY pairId
ORDER BY totalRewards DESC;
```

## 🔄 Future Enhancements

- [ ] Dynamic emissions adjustment based on market conditions
- [ ] Cross-pair liquidity multipliers
- [ ] NFT-based tier system
- [ ] Integration with price oracles for USD-based rewards
- [ ] Auto-compounding reward engine
- [ ] Advanced analytics dashboard
- [ ] Mobile app integration
- [ ] Referral program for LP recruitment

## 📖 Documentation

See related files:
- [Smart Contract API](Contracts/contracts/liquidity-mining/src/lib.rs)
- [Database Schema](Backend/prisma/schema.prisma)
- [Service Implementation](Backend/src/liquidity-mining/liquidity-mining.service.ts)
- [API Controllers](Backend/src/liquidity-mining/liquidity-mining.controller.ts)

## ✅ Acceptance Criteria Met

- ✅ Track LP token balances over time
- ✅ Calculate rewards per block/epoch
- ✅ Configurable emission rates per pair
- ✅ Bonus for long-term staking (2x-5x)
- ✅ Claim rewards functionality
- ✅ APR/APY display
- ✅ Governance power from locked rewards
- ✅ Complete audit trail
- ✅ Smart contract on Soroban
- ✅ Backend service with persistence
- ✅ Comprehensive API endpoints
- ✅ Integration test suite

## 🤝 Contributing

To contribute to the liquidity mining program:
1. Create a feature branch from `main`
2. Add tests for new functionality
3. Update schema.prisma for data changes
4. Update this README with new features
5. Submit PR for review

## 📄 License

Stellara Liquidity Mining Program © 2026
