import { Injectable, Logger, NotFoundException, BadRequestException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { Decimal } from '@prisma/client/runtime/library';
import {
  CreateLiquidityMiningPairDto,
  ProvideLiquidityDto,
  WithdrawLiquidityDto,
  ClaimRewardsDto,
  LockRewardsForGovernanceDto,
  UserLiquidityStatsDto,
  PairStatisticsDto,
  GetPendingRewardsResponseDto,
  PairResponseDto,
  LPStakeResponseDto,
  RewardClaimResponseDto,
  GovernanceLockResponseDto,
} from './liquidity-mining.dto';

@Injectable()
export class LiquidityMiningService {
  private readonly logger = new Logger(LiquidityMiningService.name);

  // Bonus multiplier tiers (in basis points: 100 = 1x, 200 = 2x, etc.)
  private readonly MULTIPLIER_TIERS = {
    TIER_1: { days: 30, multiplier: 200 },    // 2x
    TIER_2: { days: 90, multiplier: 300 },    // 3x
    TIER_3: { days: 180, multiplier: 500 },   // 5x
  };

  // Default emissions configuration
  private readonly BLOCKS_PER_YEAR = 6500 * 365; // ~6500 blocks per day

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Create a new liquidity mining pair
   */
  async createPair(dto: CreateLiquidityMiningPairDto): Promise<PairResponseDto> {
    const existingPair = await this.prisma.liquidityMiningPair.findUnique({
      where: { pairId: dto.pairId },
    });

    if (existingPair) {
      throw new ConflictException(`Pair with ID ${dto.pairId} already exists`);
    }

    const pair = await this.prisma.liquidityMiningPair.create({
      data: {
        pairId: dto.pairId,
        pairSymbol: dto.pairSymbol,
        emissionsPerBlock: new Decimal(dto.emissionsPerBlock),
        totalAllocated: new Decimal(dto.totalAllocated),
        lastUpdateBlock: BigInt(0),
        active: true,
      },
    });

    this.logger.log(`Created liquidity mining pair: ${dto.pairSymbol} (ID: ${dto.pairId})`);

    return this.mapPairToDto(pair);
  }

  /**
   * Get all active pairs
   */
  async getAllPairs(onlyActive: boolean = true): Promise<PairResponseDto[]> {
    const pairs = await this.prisma.liquidityMiningPair.findMany({
      where: onlyActive ? { active: true } : {},
      orderBy: { createdAt: 'desc' },
    });

    return pairs.map(pair => this.mapPairToDto(pair));
  }

  /**
   * Get a specific pair by ID
   */
  async getPairById(pairId: number): Promise<PairResponseDto> {
    const pair = await this.prisma.liquidityMiningPair.findUnique({
      where: { pairId },
    });

    if (!pair) {
      throw new NotFoundException(`Pair with ID ${pairId} not found`);
    }

    return this.mapPairToDto(pair);
  }

  /**
   * Provide liquidity to a pair
   */
  async provideLiquidity(dto: ProvideLiquidityDto): Promise<LPStakeResponseDto> {
    // Validate pair exists and is active
    const pair = await this.prisma.liquidityMiningPair.findUnique({
      where: { pairId: dto.pairId },
    });

    if (!pair) {
      throw new NotFoundException(`Pair with ID ${dto.pairId} not found`);
    }

    if (!pair.active) {
      throw new BadRequestException(`Pair with ID ${dto.pairId} is not active`);
    }

    const lpAmount = new Decimal(dto.lpAmount);
    if (lpAmount.lte(0)) {
      throw new BadRequestException('LP amount must be positive');
    }

    // Get or create LP stake
    let lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: {
          userAddress: dto.userAddress,
          pairId: dto.pairId,
        },
      },
    });

    const now = new Date();
    let lockedUntil: Date | null = null;

    // Calculate locked until date based on multiplier tier
    if (dto.bonusMultiplierTier && dto.bonusMultiplierTier > 0) {
      const tierConfig = this.getMultiplierTierConfig(dto.bonusMultiplierTier);
      if (!tierConfig) {
        throw new BadRequestException(`Invalid bonus multiplier tier: ${dto.bonusMultiplierTier}`);
      }
      lockedUntil = new Date(now.getTime() + tierConfig.days * 24 * 60 * 60 * 1000);
    }

    if (lpStake) {
      // Update existing stake
      lpStake = await this.prisma.lPStake.update({
        where: {
          userAddress_pairId: {
            userAddress: dto.userAddress,
            pairId: dto.pairId,
          },
        },
        data: {
          lpBalance: lpStake.lpBalance.plus(lpAmount),
          bonusMultiplierTier: dto.bonusMultiplierTier || lpStake.bonusMultiplierTier,
          lockedUntil: lockedUntil || lpStake.lockedUntil,
          updatedAt: now,
        },
      });
    } else {
      // Create new stake
      lpStake = await this.prisma.lPStake.create({
        data: {
          userAddress: dto.userAddress,
          pairId: dto.pairId,
          lpBalance: lpAmount,
          startTimestamp: now,
          bonusMultiplierTier: dto.bonusMultiplierTier || 0,
          lockedUntil,
        },
      });
    }

    // Log event
    await this.prisma.liquidityMiningEvent.create({
      data: {
        userAddress: dto.userAddress,
        eventType: 'provide_liquidity',
        pairId: dto.pairId,
        amount: lpAmount,
      },
    });

    this.logger.log(`User ${dto.userAddress} provided ${dto.lpAmount} LP to pair ${dto.pairId}`);

    return this.mapLPStakeToDto(lpStake);
  }

  /**
   * Withdraw liquidity from a pair
   */
  async withdrawLiquidity(dto: WithdrawLiquidityDto): Promise<LPStakeResponseDto> {
    const lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: {
          userAddress: dto.userAddress,
          pairId: dto.pairId,
        },
      },
    });

    if (!lpStake) {
      throw new NotFoundException(
        `No LP stake found for user ${dto.userAddress} in pair ${dto.pairId}`
      );
    }

    const withdrawAmount = new Decimal(dto.lpAmount);

    if (withdrawAmount.lte(0)) {
      throw new BadRequestException('Withdrawal amount must be positive');
    }

    if (withdrawAmount.gt(lpStake.lpBalance)) {
      throw new BadRequestException(
        `Insufficient LP balance. Available: ${lpStake.lpBalance}, Requested: ${withdrawAmount}`
      );
    }

    // Check lockup period
    if (lpStake.lockedUntil && lpStake.lockedUntil > new Date()) {
      throw new BadRequestException(
        `Liquidity is locked until ${lpStake.lockedUntil}. Cannot withdraw yet.`
      );
    }

    // Claim pending rewards before withdrawal
    const pendingRewards = await this.calculatePendingRewards(dto.userAddress, dto.pairId);
    if (pendingRewards.gt(0)) {
      await this.claimRewardsInternal(dto.userAddress, dto.pairId);
    }

    // Update stake
    const updatedStake = await this.prisma.lPStake.update({
      where: {
        userAddress_pairId: {
          userAddress: dto.userAddress,
          pairId: dto.pairId,
        },
      },
      data: {
        lpBalance: lpStake.lpBalance.minus(withdrawAmount),
        updatedAt: new Date(),
      },
    });

    // Log event
    await this.prisma.liquidityMiningEvent.create({
      data: {
        userAddress: dto.userAddress,
        eventType: 'withdraw_liquidity',
        pairId: dto.pairId,
        amount: withdrawAmount,
      },
    });

    this.logger.log(`User ${dto.userAddress} withdrew ${dto.lpAmount} LP from pair ${dto.pairId}`);

    return this.mapLPStakeToDto(updatedStake);
  }

  /**
   * Calculate pending rewards for a user in a pair
   */
  async calculatePendingRewards(userAddress: string, pairId: number): Promise<Decimal> {
    const lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: { userAddress, pairId },
      },
    });

    if (!lpStake || lpStake.lpBalance.lte(0)) {
      return new Decimal(0);
    }

    const pair = await this.prisma.liquidityMiningPair.findUnique({
      where: { pairId },
    });

    if (!pair) {
      return new Decimal(0);
    }

    // Get total LP staked across all users in this pair
    const totalStaked = await this.prisma.lPStake.aggregate({
      where: { pairId },
      _sum: { lpBalance: true },
    });

    const totalLp = totalStaked._sum.lpBalance || new Decimal(0);

    if (totalLp.lte(0)) {
      return new Decimal(0);
    }

    // Calculate base reward: (userLP / totalLP) * emissionsPerBlock * blocksElapsed
    // For simplicity, using fixed 6500 blocks per day
    const blocksElapsed = new Decimal(1); // In real implementation, track actual block numbers
    const baseReward = lpStake.lpBalance
      .div(totalLp)
      .mul(pair.emissionsPerBlock)
      .mul(blocksElapsed);

    // Apply bonus multiplier
    const multiplier = this.getMultiplierValue(lpStake.bonusMultiplierTier);
    const finalReward = baseReward.mul(multiplier).div(100);

    return finalReward.minus(lpStake.rewardDebt);
  }

  /**
   * Get pending rewards with formatted response
   */
  async getPendingRewards(userAddress: string, pairId: number): Promise<GetPendingRewardsResponseDto> {
    const pending = await this.calculatePendingRewards(userAddress, pairId);

    const lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: { userAddress, pairId },
      },
    });

    const multiplierValue = lpStake ? this.getMultiplierValue(lpStake.bonusMultiplierTier) : 100;

    return {
      userAddress,
      pairId,
      pendingRewardAmount: pending.toString(),
      bonusMultiplier: (multiplierValue / 100).toString(),
      estimatedFinalAmount: pending.toString(),
      lastClaimTime: lpStake?.updatedAt,
    };
  }

  /**
   * Claim rewards for all pairs of a user
   */
  async claimRewards(dto: ClaimRewardsDto): Promise<RewardClaimResponseDto> {
    const reward = await this.claimRewardsInternal(dto.userAddress, dto.pairId);
    return reward;
  }

  /**
   * Lock rewards for governance power
   */
  async lockRewardsForGovernance(dto: LockRewardsForGovernanceDto): Promise<GovernanceLockResponseDto> {
    // Get pending rewards
    const pending = await this.calculatePendingRewards(dto.userAddress, dto.pairId);

    if (pending.lte(0)) {
      throw new BadRequestException('No pending rewards to lock');
    }

    if (dto.lockupDays < 1 || dto.lockupDays > 365) {
      throw new BadRequestException('Lockup period must be between 1 and 365 days');
    }

    // Claim the rewards first
    const claimedReward = await this.claimRewardsInternal(dto.userAddress, dto.pairId);

    // 50% of claimed rewards become governance power
    const governancePower = claimedReward.finalRewardAmount.div(2);

    const lockedUntil = new Date();
    lockedUntil.setDate(lockedUntil.getDate() + dto.lockupDays);

    const lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: { userAddress: dto.userAddress, pairId: dto.pairId },
      },
    });

    if (!lpStake) {
      throw new NotFoundException('LP stake not found');
    }

    const governanceLock = await this.prisma.governanceLock.create({
      data: {
        userAddress: dto.userAddress,
        lpStakeId: lpStake.id,
        governancePower,
        lockupDuration: dto.lockupDays,
        lockedUntil,
      },
    });

    // Log event
    await this.prisma.liquidityMiningEvent.create({
      data: {
        userAddress: dto.userAddress,
        eventType: 'lock_governance',
        pairId: dto.pairId,
        amount: governancePower,
      },
    });

    this.logger.log(
      `User ${dto.userAddress} locked ${governancePower} governance power for ${dto.lockupDays} days`
    );

    return this.mapGovernanceLockToDto(governanceLock);
  }

  /**
   * Get user's liquidity statistics
   */
  async getUserLiquidityStats(userAddress: string): Promise<UserLiquidityStatsDto> {
    const activeStakes = await this.prisma.lPStake.findMany({
      where: {
        userAddress,
        lpBalance: { gt: new Decimal(0) },
      },
    });

    const recentRewards = await this.prisma.liquidityReward.findMany({
      where: { userAddress },
      orderBy: { claimedAt: 'desc' },
      take: 10,
    });

    const governanceLocks = await this.prisma.governanceLock.findMany({
      where: { userAddress },
      orderBy: { createdAt: 'desc' },
    });

    const totalLP = activeStakes.reduce((acc, stake) => acc.plus(stake.lpBalance), new Decimal(0));
    const totalRewardsClaimed = recentRewards.reduce(
      (acc, reward) => acc.plus(reward.finalRewardAmount),
      new Decimal(0)
    );
    const totalGovernancePower = governanceLocks.reduce(
      (acc, lock) => acc.plus(lock.governancePower),
      new Decimal(0)
    );

    return {
      userAddress,
      totalLpProvided: totalLP.toString(),
      totalRewardsClaimed: totalRewardsClaimed.toString(),
      governancePower: totalGovernancePower.toString(),
      activeStakes: activeStakes.map(stake => this.mapLPStakeToDto(stake)),
      recentRewards: recentRewards.map(reward => this.mapRewardToDto(reward)),
      governanceLocks: governanceLocks.map(lock => this.mapGovernanceLockToDto(lock)),
    };
  }

  /**
   * Get statistics for a pair
   */
  async getPairStatistics(pairId: number): Promise<PairStatisticsDto> {
    const pair = await this.prisma.liquidityMiningPair.findUnique({
      where: { pairId },
    });

    if (!pair) {
      throw new NotFoundException(`Pair ${pairId} not found`);
    }

    const lpStakes = await this.prisma.lPStake.findMany({
      where: { pairId },
    });

    const totalStaked = lpStakes.reduce((acc, stake) => acc.plus(stake.lpBalance), new Decimal(0));
    const stakers = new Set(lpStakes.map(s => s.userAddress)).size;
    const avgLockupTier =
      lpStakes.length > 0
        ? Math.round(
            lpStakes.reduce((acc, s) => acc + s.bonusMultiplierTier, 0) / lpStakes.length
          )
        : 0;

    // Calculate APR/APY
    // APR = (annual emissions / total staked) * 100
    // APY = (1 + APR/365)^365 - 1 (compounding daily)
    const annualEmissions = pair.emissionsPerBlock.mul(this.BLOCKS_PER_YEAR);
    const apr = totalStaked.gt(0)
      ? annualEmissions.div(totalStaked).mul(100)
      : new Decimal(0);
    const apy = apr.gt(0)
      ? apr
        .div(365)
        .plus(1)
        .pow(365)
        .minus(1)
        .mul(100)
      : new Decimal(0);

    return {
      pairId,
      pairSymbol: pair.pairSymbol,
      totalLiquidityStaked: totalStaked.toString(),
      emissionsPerBlock: pair.emissionsPerBlock.toString(),
      aprPercentage: apr.toFixed(2),
      apyPercentage: apy.toFixed(2),
      totalStakers: stakers,
      averageLockupTier: avgLockupTier,
      active: pair.active,
    };
  }

  // ═════════════════════════════════════════════════════════════════
  // INTERNAL HELPER METHODS
  // ═════════════════════════════════════════════════════════════════

  private async claimRewardsInternal(userAddress: string, pairId: number): Promise<RewardClaimResponseDto> {
    const pending = await this.calculatePendingRewards(userAddress, pairId);

    if (pending.lte(0)) {
      throw new BadRequestException('No pending rewards to claim');
    }

    const lpStake = await this.prisma.lPStake.findUnique({
      where: {
        userAddress_pairId: { userAddress, pairId },
      },
    });

    if (!lpStake) {
      throw new NotFoundException('LP stake not found');
    }

    const multiplier = new Decimal(this.getMultiplierValue(lpStake.bonusMultiplierTier)).div(100);

    const reward = await this.prisma.liquidityReward.create({
      data: {
        userAddress,
        pairId,
        rewardAmount: pending,
        bonusMultiplier: multiplier,
        finalRewardAmount: pending,
        claimedAt: new Date(),
      },
    });

    // Update reward debt
    await this.prisma.lPStake.update({
      where: {
        userAddress_pairId: { userAddress, pairId },
      },
      data: {
        rewardDebt: lpStake.rewardDebt.plus(pending),
      },
    });

    // Log event
    await this.prisma.liquidityMiningEvent.create({
      data: {
        userAddress,
        eventType: 'claim_reward',
        pairId,
        amount: pending,
      },
    });

    this.logger.log(`User ${userAddress} claimed ${pending} rewards from pair ${pairId}`);

    return this.mapRewardToDto(reward);
  }

  private getMultiplierTierConfig(tier: number): { days: number; multiplier: number } | null {
    switch (tier) {
      case 1:
        return this.MULTIPLIER_TIERS.TIER_1;
      case 2:
        return this.MULTIPLIER_TIERS.TIER_2;
      case 3:
        return this.MULTIPLIER_TIERS.TIER_3;
      default:
        return null;
    }
  }

  private getMultiplierValue(tier: number): number {
    switch (tier) {
      case 1:
        return this.MULTIPLIER_TIERS.TIER_1.multiplier;
      case 2:
        return this.MULTIPLIER_TIERS.TIER_2.multiplier;
      case 3:
        return this.MULTIPLIER_TIERS.TIER_3.multiplier;
      default:
        return 100;
    }
  }

  private calculatePendingRewardsSync(lpBalance: Decimal, totalStaked: Decimal, pairConfig: any, bonusTier: number): Decimal {
    if (totalStaked.lte(0) || lpBalance.lte(0)) {
      return new Decimal(0);
    }

    const baseReward = lpBalance.div(totalStaked).mul(pairConfig.emissionsPerBlock);
    const multiplier = this.getMultiplierValue(bonusTier);
    return baseReward.mul(multiplier).div(100);
  }

  // ═════════════════════════════════════════════════════════════════
  // DTO MAPPING METHODS
  // ═════════════════════════════════════════════════════════════════

  private mapPairToDto(pair: any): PairResponseDto {
    return {
      id: pair.id,
      pairId: pair.pairId,
      pairSymbol: pair.pairSymbol,
      emissionsPerBlock: pair.emissionsPerBlock.toString(),
      totalAllocated: pair.totalAllocated.toString(),
      accumulatedRewardPerShare: pair.accumulatedRewardPerShare.toString(),
      lastUpdateBlock: Number(pair.lastUpdateBlock),
      active: pair.active,
      createdAt: pair.createdAt,
      updatedAt: pair.updatedAt,
    };
  }

  private mapLPStakeToDto(stake: any): LPStakeResponseDto {
    return {
      id: stake.id,
      userAddress: stake.userAddress,
      pairId: stake.pairId,
      lpBalance: stake.lpBalance.toString(),
      startTimestamp: stake.startTimestamp,
      rewardDebt: stake.rewardDebt.toString(),
      bonusMultiplierTier: stake.bonusMultiplierTier,
      lockedUntil: stake.lockedUntil,
      createdAt: stake.createdAt,
      updatedAt: stake.updatedAt,
    };
  }

  private mapRewardToDto(reward: any): RewardClaimResponseDto {
    return {
      id: reward.id,
      userAddress: reward.userAddress,
      pairId: reward.pairId,
      rewardAmount: reward.rewardAmount.toString(),
      bonusMultiplier: reward.bonusMultiplier.toString(),
      finalRewardAmount: reward.finalRewardAmount.toString(),
      claimedAt: reward.claimedAt,
      transactionHash: reward.transactionHash,
      blockNumber: reward.blockNumber ? Number(reward.blockNumber) : undefined,
      createdAt: reward.createdAt,
    };
  }

  private mapGovernanceLockToDto(lock: any): GovernanceLockResponseDto {
    return {
      id: lock.id,
      userAddress: lock.userAddress,
      governancePower: lock.governancePower.toString(),
      lockupDuration: lock.lockupDuration,
      lockedUntil: lock.lockedUntil,
      released: lock.released,
      releasedAt: lock.releasedAt,
      createdAt: lock.createdAt,
      updatedAt: lock.updatedAt,
    };
  }
}
