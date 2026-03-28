# Liquidity Mining - Backend Integration Guide

## Quick Integration

The Liquidity Mining Module is already integrated into the backend. Here's what was done:

### ✅ Files Added/Modified

**New Files**:
```
Backend/src/liquidity-mining/
├── liquidity-mining.controller.ts  # 12+ API endpoints
├── liquidity-mining.service.ts     # Business logic (850+ lines)
├── liquidity-mining.dto.ts         # 15+ data transfer objects
├── liquidity-mining.module.ts      # NestJS module
└── README.md                       # Service documentation
```

**Modified Files**:
```
Backend/src/app.module.ts
  - Added: import { LiquidityMiningModule } from './liquidity-mining/liquidity-mining.module';
  - Added: LiquidityMiningModule to imports array

Backend/prisma/schema.prisma
  - Added: 5 new models (150+ lines)
  - LiquidityMiningPair
  - LPStake
  - LiquidityReward
  - GovernanceLock
  - LiquidityMiningEvent
```

## 🚀 Deployment Steps

### 1. Database Migration
```bash
cd Backend

# Create migration
npx prisma migrate dev --name add_liquidity_mining

# Or deploy existing migration
npx prisma migrate deploy
```

### 2. Start Backend
```bash
# Development
pnpm dev

# Production
pnpm start
```

### 3. Verify API Endpoints
```bash
# Health check
curl http://localhost:3000/liquidity-mining/health

# List pairs
curl http://localhost:3000/liquidity-mining/pairs
```

## 📡 Available Endpoints

### Pair Management
```
POST   /liquidity-mining/pairs                      Create pair
GET    /liquidity-mining/pairs                      List pairs
GET    /liquidity-mining/pairs/:pairId              Get pair
GET    /liquidity-mining/pairs/:pairId/statistics   Get statistics
```

### Liquidity
```
POST   /liquidity-mining/liquidity/provide          Provide liquidity
POST   /liquidity-mining/liquidity/withdraw         Withdraw liquidity
GET    /liquidity-mining/liquidity/:userAddress/:pairId  Get stake
```

### Rewards
```
GET    /liquidity-mining/rewards/pending/:userAddress/:pairId
POST   /liquidity-mining/rewards/claim
POST   /liquidity-mining/rewards/lock-governance
```

### User Analytics
```
GET    /liquidity-mining/user/:userAddress/statistics
GET    /liquidity-mining/health
```

## 🧪 Testing the API

### Create a Pair
```bash
curl -X POST http://localhost:3000/liquidity-mining/pairs \
  -H "Content-Type: application/json" \
  -d '{
    "pairId": 1,
    "pairSymbol": "USDC_STELLAR",
    "emissionsPerBlock": "100.00",
    "totalAllocated": "1000000.00"
  }'
```

### Provide Liquidity
```bash
curl -X POST http://localhost:3000/liquidity-mining/liquidity/provide \
  -H "Content-Type: application/json" \
  -d '{
    "userAddress": "GXXXXXXXXXXXXXXXXXX",
    "pairId": 1,
    "lpAmount": "5000.00",
    "bonusMultiplierTier": 2
  }'
```

### Check Pending Rewards
```bash
curl http://localhost:3000/liquidity-mining/rewards/pending/GXXXXXXXXXXXXXXXXXX/1
```

### Claim Rewards
```bash
curl -X POST http://localhost:3000/liquidity-mining/rewards/claim \
  -H "Content-Type: application/json" \
  -d '{
    "userAddress": "GXXXXXXXXXXXXXXXXXX",
    "pairId": 1
  }'
```

### Get User Statistics
```bash
curl http://localhost:3000/liquidity-mining/user/GXXXXXXXXXXXXXXXXXX/statistics
```

## 🗄️ Database Schema

The following tables are created:

```sql
-- Pair configurations
CREATE TABLE liquidity_mining_pairs (
  id UUID PRIMARY KEY,
  pair_id INT UNIQUE NOT NULL,
  pair_symbol VARCHAR NOT NULL,
  emissions_per_block DECIMAL(18,4),
  total_allocated DECIMAL(18,4),
  accumulated_reward_per_share DECIMAL(18,4),
  last_update_block BIGINT,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

-- User LP stakes
CREATE TABLE lp_stakes (
  id UUID PRIMARY KEY,
  user_address VARCHAR NOT NULL,
  pair_id INT NOT NULL,
  lp_balance DECIMAL(18,4),
  start_timestamp TIMESTAMP,
  reward_debt DECIMAL(18,4),
  bonus_multiplier_tier INT DEFAULT 0,
  locked_until TIMESTAMP,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  UNIQUE(user_address, pair_id),
  FOREIGN KEY(pair_id) REFERENCES liquidity_mining_pairs(pair_id)
);

-- Claimed rewards
CREATE TABLE liquidity_rewards (
  id UUID PRIMARY KEY,
  user_address VARCHAR NOT NULL,
  pair_id INT NOT NULL,
  reward_amount DECIMAL(18,4),
  bonus_multiplier DECIMAL(5,2),
  final_reward_amount DECIMAL(18,4),
  claimed_at TIMESTAMP,
  transaction_hash VARCHAR,
  block_number BIGINT,
  created_at TIMESTAMP,
  FOREIGN KEY(pair_id) REFERENCES liquidity_mining_pairs(pair_id)
);

-- Locked governance power
CREATE TABLE governance_locks (
  id UUID PRIMARY KEY,
  user_address VARCHAR NOT NULL,
  lp_stake_id UUID NOT NULL,
  governance_power DECIMAL(18,4),
  lockup_duration INT,
  locked_until TIMESTAMP,
  released BOOLEAN DEFAULT false,
  released_at TIMESTAMP,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  FOREIGN KEY(lp_stake_id) REFERENCES lp_stakes(id)
);

-- Event audit trail
CREATE TABLE liquidity_mining_events (
  id UUID PRIMARY KEY,
  user_address VARCHAR NOT NULL,
  event_type VARCHAR NOT NULL,
  pair_id INT,
  amount DECIMAL(18,4),
  metadata JSONB,
  transaction_hash VARCHAR,
  block_number BIGINT,
  created_at TIMESTAMP
);
```

## 🔍 Database Queries

### Get total liquidity per pair
```sql
SELECT pairId, SUM(lpBalance) as totalLiquidity
FROM lp_stakes
WHERE lpBalance > 0
GROUP BY pairId;
```

### Get top LP providers
```sql
SELECT userAddress, SUM(lpBalance) as totalLP
FROM lp_stakes
WHERE lpBalance > 0
GROUP BY userAddress
ORDER BY totalLP DESC
LIMIT 20;
```

### Get reward distribution
```sql
SELECT pairId, SUM(finalRewardAmount) as totalRewards, COUNT(*) as claims
FROM liquidity_rewards
GROUP BY pairId;
```

### Get user's governance power
```sql
SELECT SUM(governancePower) as totalPower
FROM governance_locks
WHERE userAddress = 'GXXXXXXXXXXXXXXXXXX' AND released = false;
```

## 🛠️ Environment Variables

Ensure these are set in `.env`:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/stellara
REDIS_HOST=localhost
REDIS_PORT=6379
NODE_ENV=development
```

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:3000/liquidity-mining/health
```

### Database Connectivity
The service will automatically create indexes on the following columns:
- `lp_stakes(userAddress, pairId)`
- `liquidity_rewards(userAddress, pairId)`
- `governance_locks(userAddress, lockedUntil)`
- `liquidity_mining_events(userAddress, eventType)`

## 🐛 Troubleshooting

### Database Connection Error
```
Error: P1000 - Authentication failed against database server
Solution: Check DATABASE_URL in .env
```

### Migration Failed
```bash
# Rollback and retry
npx prisma migrate reset
npx prisma migrate deploy
```

### Service not responding
```bash
# Check if service is running
ps aux | grep node

# Check logs
tail -f logs/app.log

# Restart
pnpm start
```

## 📚 Documentation

- **Service Implementation**: `Backend/src/liquidity-mining/README.md`
- **API DTOs**: `Backend/src/liquidity-mining/liquidity-mining.dto.ts`
- **Service Logic**: `Backend/src/liquidity-mining/liquidity-mining.service.ts`
- **Database Schema**: `Backend/prisma/schema.prisma`
- **Implementation Summary**: `LIQUIDITY_MINING_IMPLEMENTATION.md`

## 🚢 Production Checklist

- [ ] Database backups enabled
- [ ] Connection pooling configured
- [ ] Rate limiting enabled
- [ ] New Relic/APM configured (optional)
- [ ] Monitoring alerts set up
- [ ] Error tracking configured
- [ ] API documentation published
- [ ] Load testing completed
- [ ] Security audit passed
- [ ] Health checks passing
