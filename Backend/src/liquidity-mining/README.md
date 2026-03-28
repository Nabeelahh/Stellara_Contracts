# Liquidity Mining Backend Service

Off-chain service layer for the Liquidity Mining Program, providing data persistence, analytics, and API endpoints.

## 📁 Structure

```
Backend/src/liquidity-mining/
├── liquidity-mining.controller.ts  # REST API endpoints
├── liquidity-mining.service.ts      # Business logic & calculations
├── liquidity-mining.dto.ts          # Data transfer objects
└── liquidity-mining.module.ts       # NestJS module configuration
```

## 🏗️ Architecture

### Service Layer (`liquidity-mining.service.ts`)

**Core Methods**:

#### Pair Management
- `createPair(dto)` - Register new mining pair
- `getAllPairs(onlyActive?)` - List all pairs
- `getPairById(pairId)` - Get specific pair

#### Liquidity Operations
- `provideLiquidity(dto)` - User deposits LP tokens
- `withdrawLiquidity(dto)` - User withdraws LP tokens
  - Validates lockup period
  - Auto-claims pending rewards
  - Updates LP balance

#### Reward Calculations
- `calculatePendingRewards(userAddress, pairId)` - Computes accrued rewards
  - Gets user's LP balance
  - Gets total LP staked in pair
  - Calculates blocks elapsed
  - Applies bonus multiplier
  - Subtracts reward debt
- `getPendingRewards(userAddress, pairId)` - Returns formatted response

#### Reward Claims
- `claimRewards(dto)` - User claims accumulated rewards
- `lockRewardsForGovernance(dto)` - Lock 50% of rewards
  - Claims rewards first
  - Allocates 50% to governance
  - Calculates lockup expiration

#### Analytics
- `getUserLiquidityStats(userAddress)` - Complete user profile
  - All active stakes
  - Reward history (last 10)
  - Governance locks
  - Total metrics
- `getPairStatistics(pairId)` - Pair analytics
  - Total liquidity
  - Total stakers
  - APR/APY calculation
  - Average lockup tier

### Controller Layer (`liquidity-mining.controller.ts`)

RESTful API endpoints organized by functionality:

**Pair Management**:
```
POST   /liquidity-mining/pairs
GET    /liquidity-mining/pairs
GET    /liquidity-mining/pairs/:pairId
GET    /liquidity-mining/pairs/:pairId/statistics
```

**Liquidity Provision**:
```
POST   /liquidity-mining/liquidity/provide
POST   /liquidity-mining/liquidity/withdraw
GET    /liquidity-mining/liquidity/:userAddress/:pairId
```

**Rewards**:
```
GET    /liquidity-mining/rewards/pending/:userAddress/:pairId
POST   /liquidity-mining/rewards/claim
POST   /liquidity-mining/rewards/lock-governance
```

**Analytics**:
```
GET    /liquidity-mining/user/:userAddress/statistics
GET    /liquidity-mining/health
```

### Data Layer (Prisma)

**Models**:
```typescript
// Trading pair configuration
LiquidityMiningPair {
  pairId, pairSymbol, emissionsPerBlock, totalAllocated
  accumulatedRewardPerShare, lastUpdateBlock, active
}

// User LP stakes
LPStake {
  userAddress, pairId, lpBalance, startTimestamp
  rewardDebt, bonusMultiplierTier, lockedUntil
}

// Claimed rewards
LiquidityReward {
  userAddress, pairId, rewardAmount, bonusMultiplier
  finalRewardAmount, claimedAt, transactionHash, blockNumber
}

// Locked governance power
GovernanceLock {
  userAddress, lpStakeId, governancePower, lockupDuration
  lockedUntil, released, releasedAt
}

// Event audit log
LiquidityMiningEvent {
  userAddress, eventType, pairId, amount
  metadata, transactionHash, blockNumber, createdAt
}
```

## 🔄 Data Flow

### Provide Liquidity Flow
```
1. POST /liquidity-mining/liquidity/provide
   ↓
2. provideLiquidity(dto)
   ↓
3. Validate pair exists & active
   ↓
4. Find or create LPStake record
   ↓
5. Calculate lockup expiration date
   ↓
6. Update LPStake in database
   ↓
7. Create LiquidityMiningEvent
   ↓
8. Return LPStakeResponseDto
```

### Claim Rewards Flow
```
1. POST /liquidity-mining/rewards/claim
   ↓
2. claimRewards(dto)
   ↓
3. calculatePendingRewards(userAddress, pairId)
   ↓
4. Query LPStake & LiquidityMiningPair
   ↓
5. Get total LP staked (aggregate query)
   ↓
6. Calculate: base_reward × (user_lp / total_lp) × emissions × blocks
   ↓
7. Apply bonus multiplier
   ↓
8. Create LiquidityReward record
   ↓
9. Update LPStake.rewardDebt
   ↓
10. Create LiquidityMiningEvent
    ↓
11. Return RewardClaimResponseDto
```

## 💡 Key Implementation Details

### Decimal Precision Handling

Uses Prisma's `Decimal` type for precise financial calculations:

```typescript
import { Decimal } from '@prisma/client/runtime/library';

// Safe arithmetic
const reward = lpBalance
  .div(totalStaked)
  .mul(emissionsPerBlock)
  .mul(new Decimal(1))  // blocks elapsed
  
const withMultiplier = reward
  .mul(multiplier)
  .div(100)
```

### Bonus Multiplier System

```typescript
private readonly MULTIPLIER_TIERS = {
  TIER_1: { days: 30, multiplier: 200 },    // 2x
  TIER_2: { days: 90, multiplier: 300 },    // 3x
  TIER_3: { days: 180, multiplier: 500 },   // 5x
};

private getMultiplierValue(tier: number): number {
  // Returns basis points (100 = 1x, 200 = 2x, etc.)
  switch(tier) {
    case 1: return 200;
    case 2: return 300;
    case 3: return 500;
    default: return 100;
  }
}
```

### Lockup Period Enforcement

```typescript
if (lpStake.lockedUntil && lpStake.lockedUntil > new Date()) {
  throw new BadRequestException(
    `Liquidity is locked until ${lpStake.lockedUntil}`
  );
}
```

### Automatic Reward Claiming on Withdrawal

```typescript
async withdrawLiquidity(dto) {
  // Claim pending rewards before withdrawal
  const pending = await this.calculatePendingRewards(...);
  if (pending > 0) {
    await this.claimRewardsInternal(...);
  }
  // Then proceed with withdrawal
}
```

### APR/APY Calculation

```typescript
const BLOCKS_PER_YEAR = 6500 * 365;  // blocks/day × days/year

const annualEmissions = emissionsPerBlock.mul(BLOCKS_PER_YEAR);
const apr = annualEmissions.div(totalStaked).mul(100);
const apy = apr
  .div(365)
  .plus(1)
  .pow(365)
  .minus(1)
  .mul(100);
```

## 📝 DTOs

### Request DTOs

**ProvideLiquidityDto**
```typescript
{
  userAddress: string;
  pairId: number;
  lpAmount: string;                  // Decimal precision string
  bonusMultiplierTier?: number;      // 0-3
}
```

**ClaimRewardsDto**
```typescript
{
  userAddress: string;
  pairId: number;
  transactionHash?: string;
}
```

**LockRewardsForGovernanceDto**
```typescript
{
  userAddress: string;
  pairId: number;
  lockupDays: number;                // 1-365
}
```

### Response DTOs

**LPStakeResponseDto**
```typescript
{
  id: string;
  userAddress: string;
  pairId: number;
  lpBalance: string;
  startTimestamp: Date;
  rewardDebt: string;
  bonusMultiplierTier: number;
  lockedUntil?: Date;
  createdAt: Date;
  updatedAt: Date;
}
```

**RewardClaimResponseDto**
```typescript
{
  id: string;
  userAddress: string;
  pairId: number;
  rewardAmount: string;
  bonusMultiplier: string;
  finalRewardAmount: string;
  claimedAt: Date;
  transactionHash?: string;
  blockNumber?: number;
  createdAt: Date;
}
```

## 🧪 Testing

Service tests should cover:

1. **Pair Operations**
   - Create pair with valid params
   - Prevent duplicate pairs
   - List active/all pairs

2. **Liquidity Provision**
   - Provide with valid amount
   - Provide with multiplier tier
   - Prevent zero/negative amounts
   - Track balance correctly

3. **Reward Calculations**
   - Base reward proportional to LP share
   - Multiplier applied correctly
   - No rewards without liquidity
   - Pending rewards decrease after claim

4. **Lockup Enforcement**
   - Cannot withdraw before lockup
   - Can withdraw after lockup
   - Correct lockup duration for each tier

5. **Governance Locking**
   - 50% of rewards locked
   - Correct governance power allocated
   - Lockup expiration dates tracked

6. **Error Handling**
   - Pair not found
   - Insufficient balance
   - Invalid multiplier tier
   - No pending rewards

```bash
# Run tests
pnpm test src/liquidity-mining/liquidity-mining.service.spec.ts

# With coverage
pnpm test:cov src/liquidity-mining
```

## 📊 Database Queries

### Get user's total governance power
```sql
SELECT 
  SUM(governancePower) as totalGovernancePower
FROM governance_locks
WHERE userAddress = $1 AND released = false;
```

### Get top 10 pairs by total liquidity
```sql
SELECT 
  lmp.pairId,
  lmp.pairSymbol,
  SUM(ls.lpBalance) as totalLiquidity,
  AVG(ls.bonusMultiplierTier) as avgMultiplierTier
FROM liquidity_mining_pairs lmp
LEFT JOIN lp_stakes ls ON lmp.pairId = ls.pairId
WHERE lmp.active = true
GROUP BY lmp.pairId, lmp.pairSymbol
ORDER BY totalLiquidity DESC
LIMIT 10;
```

### Get user's reward history
```sql
SELECT *
FROM liquidity_rewards
WHERE userAddress = $1
ORDER BY claimedAt DESC
LIMIT 10;
```

### Calculate pair APR/APY
```sql
WITH pair_stats AS (
  SELECT 
    pairId,
    SUM(lpBalance) as totalStaked
  FROM lp_stakes
  WHERE pairId = $1
  GROUP BY pairId
)
SELECT 
  lmp.emissionsPerBlock,
  ps.totalStaked,
  (lmp.emissionsPerBlock * 6500 * 365 / ps.totalStaked * 100) as apr
FROM liquidity_mining_pairs lmp
CROSS JOIN pair_stats ps
WHERE lmp.pairId = $1;
```

## 🔒 Security & Validation

### Input Validation
- User addresses validated as Stellar addresses
- Amount validation (must be positive, decimal precision)
- Pair ID must exist
- Multiplier tier 0-3 only
- Lockup days 1-365

### Authorization
- Can only claim own rewards
- Can only withdraw own liquidity
- Admin-only pair creation

### Error Handling
```typescript
throw new NotFoundException('Resource not found');
throw new BadRequestException('Invalid request');
throw new ConflictException('Resource already exists');
throw new UnauthorizedException('Not allowed');
```

## 📈 Monitoring

### Key Metrics
```typescript
// Monitor these
- Active LPs per pair
- Total TVL by pair
- Average claim frequency
- Governance power accumulation rate
- Reward distribution efficiency
```

### Logging
```typescript
this.logger.log(`User ${address} provided ${amount} LP`);
this.logger.log(`User ${address} claimed ${amount} rewards`);
this.logger.error(`Failed to process rewards for pair ${pairId}`, error);
```

## 🚀 Deployment Checklist

- [ ] Prisma migrations deployed
- [ ] Environment variables configured
- [ ] Redis connection verified
- [ ] Database backups enabled
- [ ] Rate limiting configured
- [ ] Logging enabled
- [ ] Error tracking (Sentry) configured
- [ ] API documentation generated
- [ ] Health checks passing
- [ ] Performance tests passing

## 📚 Related Documentation

- [Smart Contract Implementation](../../../Contracts/contracts/liquidity-mining/src/lib.rs)
- [Database Schema](../../../Backend/prisma/schema.prisma)
- [API Endpoints](./liquidity-mining.controller.ts)
- [DTOs Reference](./liquidity-mining.dto.ts)

## 🔗 Integration Points

**External Systems**:
- Stellar blockchain for liquidmining transactions
- Redis for caching (optional)
- PostgreSQL for persistence
- Event indexer for on-chain event tracking

**Internal Services**:
- Prisma ORM ✓
- Logging Module
- Auth Module (if needed)
- Monitoring Module
