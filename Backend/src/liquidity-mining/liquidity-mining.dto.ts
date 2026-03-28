import {
  IsString,
  IsNumber,
  IsOptional,
  IsArray,
  ValidateNested,
  Min,
  Max,
  IsBoolean,
  IsDateString,
  IsPositive,
  Matches,
} from 'class-validator';
import { Type } from 'class-transformer';

// ═══════════════════════════════════════════════════════════════════════
// PAIR MANAGEMENT DTOs
// ═══════════════════════════════════════════════════════════════════════

export class CreateLiquidityMiningPairDto {
  @IsNumber()
  @Min(0)
  pairId: number;

  @IsString()
  pairSymbol: string; // e.g., "USDC_STELLAR"

  @IsString()
  @IsPositive()
  emissionsPerBlock: string; // Use string for Decimal precision

  @IsString()
  @IsPositive()
  totalAllocated: string;
}

export class UpdatePairStatusDto {
  @IsNumber()
  pairId: number;

  @IsBoolean()
  active: boolean;
}

export class PairResponseDto {
  id: string;
  pairId: number;
  pairSymbol: string;
  emissionsPerBlock: string;
  totalAllocated: string;
  accumulatedRewardPerShare: string;
  lastUpdateBlock: number;
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// ═══════════════════════════════════════════════════════════════════════
// LIQUIDITY PROVISION DTOs
// ═══════════════════════════════════════════════════════════════════════

export class ProvideLiquidityDto {
  @IsString()
  userAddress: string;

  @IsNumber()
  pairId: number;

  @IsString()
  @IsPositive()
  lpAmount: string; // Amount of LP tokens to provide

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(3)
  bonusMultiplierTier?: number; // 0=none, 1=2x (30 days), 2=3x (90 days), 3=5x (180 days)
}

export class WithdrawLiquidityDto {
  @IsString()
  userAddress: string;

  @IsNumber()
  pairId: number;

  @IsString()
  @IsPositive()
  lpAmount: string;
}

export class LPStakeResponseDto {
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

// ═══════════════════════════════════════════════════════════════════════
// REWARD CLAIMING DTOs
// ═══════════════════════════════════════════════════════════════════════

export class ClaimRewardsDto {
  @IsString()
  userAddress: string;

  @IsNumber()
  pairId: number;

  @IsOptional()
  @IsString()
  transactionHash?: string;
}

export class LockRewardsForGovernanceDto {
  @IsString()
  userAddress: string;

  @IsNumber()
  pairId: number;

  @IsNumber()
  @Min(1)
  @Max(365)
  lockupDays: number;
}

export class RewardClaimResponseDto {
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

// ═══════════════════════════════════════════════════════════════════════
// GOVERNANCE DTOs
// ═══════════════════════════════════════════════════════════════════════

export class GovernanceLockResponseDto {
  id: string;
  userAddress: string;
  governancePower: string;
  lockupDuration: number;
  lockedUntil: Date;
  released: boolean;
  releasedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// ═══════════════════════════════════════════════════════════════════════
// ANALYTICS & QUERY DTOs
// ═══════════════════════════════════════════════════════════════════════

export class UserLiquidityStatsDto {
  userAddress: string;
  totalLpProvided: string;
  totalRewardsClaimed: string;
  governancePower: string;
  activeStakes: LPStakeResponseDto[];
  recentRewards: RewardClaimResponseDto[];
  governanceLocks: GovernanceLockResponseDto[];
}

export class PairStatisticsDto {
  pairId: number;
  pairSymbol: string;
  totalLiquidityStaked: string;
  emissionsPerBlock: string;
  aprPercentage: string;
  apyPercentage: string;
  totalStakers: number;
  averageLockupTier: number;
  active: boolean;
}

export class PaginationDto {
  @IsNumber()
  @Min(1)
  page: number = 1;

  @IsNumber()
  @Min(1)
  @Max(100)
  limit: number = 20;
}

export class GetPendingRewardsResponseDto {
  userAddress: string;
  pairId: number;
  pendingRewardAmount: string;
  bonusMultiplier: string;
  estimatedFinalAmount: string;
  lastClaimTime?: Date;
}

export class ContractInteractionDto {
  @IsString()
  contractAddress: string;

  @IsString()
  functionName: string;

  @IsArray()
  @IsOptional()
  params?: any[];
}
