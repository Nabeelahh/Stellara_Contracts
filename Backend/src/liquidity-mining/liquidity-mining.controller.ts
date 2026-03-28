import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { LiquidityMiningService } from './liquidity-mining.service';
import {
  CreateLiquidityMiningPairDto,
  ProvideLiquidityDto,
  WithdrawLiquidityDto,
  ClaimRewardsDto,
  LockRewardsForGovernanceDto,
  PairResponseDto,
  LPStakeResponseDto,
  RewardClaimResponseDto,
  GovernanceLockResponseDto,
  UserLiquidityStatsDto,
  PairStatisticsDto,
  GetPendingRewardsResponseDto,
  PaginationDto,
} from './liquidity-mining.dto';

@Controller('liquidity-mining')
export class LiquidityMiningController {
  constructor(private readonly liquidityMiningService: LiquidityMiningService) {}

  // ═════════════════════════════════════════════════════════════════
  // PAIR MANAGEMENT ENDPOINTS
  // ═════════════════════════════════════════════════════════════════

  /**
   * @route POST /liquidity-mining/pairs
   * @desc Create a new liquidity mining pair (admin only)
   */
  @Post('pairs')
  @HttpCode(HttpStatus.CREATED)
  async createPair(@Body() dto: CreateLiquidityMiningPairDto): Promise<PairResponseDto> {
    return this.liquidityMiningService.createPair(dto);
  }

  /**
   * @route GET /liquidity-mining/pairs
   * @desc Get all active liquidity mining pairs
   */
  @Get('pairs')
  @HttpCode(HttpStatus.OK)
  async getAllPairs(
    @Query('active') active?: string
  ): Promise<PairResponseDto[]> {
    const onlyActive = active !== 'false';
    return this.liquidityMiningService.getAllPairs(onlyActive);
  }

  /**
   * @route GET /liquidity-mining/pairs/:pairId
   * @desc Get details of a specific pair
   */
  @Get('pairs/:pairId')
  @HttpCode(HttpStatus.OK)
  async getPairById(@Param('pairId') pairId: string): Promise<PairResponseDto> {
    return this.liquidityMiningService.getPairById(parseInt(pairId, 10));
  }

  /**
   * @route GET /liquidity-mining/pairs/:pairId/statistics
   * @desc Get statistics for a pair (total liquidity, APR/APY, stakers)
   */
  @Get('pairs/:pairId/statistics')
  @HttpCode(HttpStatus.OK)
  async getPairStatistics(@Param('pairId') pairId: string): Promise<PairStatisticsDto> {
    return this.liquidityMiningService.getPairStatistics(parseInt(pairId, 10));
  }

  // ═════════════════════════════════════════════════════════════════
  // LIQUIDITY PROVISION ENDPOINTS
  // ═════════════════════════════════════════════════════════════════

  /**
   * @route POST /liquidity-mining/liquidity/provide
   * @desc Provide liquidity to a pair
   */
  @Post('liquidity/provide')
  @HttpCode(HttpStatus.CREATED)
  async provideLiquidity(@Body() dto: ProvideLiquidityDto): Promise<LPStakeResponseDto> {
    return this.liquidityMiningService.provideLiquidity(dto);
  }

  /**
   * @route POST /liquidity-mining/liquidity/withdraw
   * @desc Withdraw liquidity from a pair
   */
  @Post('liquidity/withdraw')
  @HttpCode(HttpStatus.OK)
  async withdrawLiquidity(@Body() dto: WithdrawLiquidityDto): Promise<LPStakeResponseDto> {
    return this.liquidityMiningService.withdrawLiquidity(dto);
  }

  /**
   * @route GET /liquidity-mining/liquidity/:userAddress/:pairId
   * @desc Get user's LP stake for a specific pair
   */
  @Get('liquidity/:userAddress/:pairId')
  @HttpCode(HttpStatus.OK)
  async getUserLPStake(
    @Param('userAddress') userAddress: string,
    @Param('pairId') pairId: string
  ): Promise<{ message: string; data: any }> {
    // This would need to be implemented in the service
    return {
      message: 'Get user LP stake',
      data: {},
    };
  }

  // ═════════════════════════════════════════════════════════════════
  // REWARD MANAGEMENT ENDPOINTS
  // ═════════════════════════════════════════════════════════════════

  /**
   * @route GET /liquidity-mining/rewards/pending/:userAddress/:pairId
   * @desc Get pending rewards for a user in a pair
   */
  @Get('rewards/pending/:userAddress/:pairId')
  @HttpCode(HttpStatus.OK)
  async getPendingRewards(
    @Param('userAddress') userAddress: string,
    @Param('pairId') pairId: string
  ): Promise<GetPendingRewardsResponseDto> {
    return this.liquidityMiningService.getPendingRewards(
      userAddress,
      parseInt(pairId, 10)
    );
  }

  /**
   * @route POST /liquidity-mining/rewards/claim
   * @desc Claim accumulated rewards for a pair
   */
  @Post('rewards/claim')
  @HttpCode(HttpStatus.OK)
  async claimRewards(@Body() dto: ClaimRewardsDto): Promise<RewardClaimResponseDto> {
    return this.liquidityMiningService.claimRewards(dto);
  }

  /**
   * @route POST /liquidity-mining/rewards/lock-governance
   * @desc Lock rewards for governance power
   * @description Locks 50% of claimed rewards as governance tokens for voting power
   */
  @Post('rewards/lock-governance')
  @HttpCode(HttpStatus.CREATED)
  async lockRewardsForGovernance(
    @Body() dto: LockRewardsForGovernanceDto
  ): Promise<GovernanceLockResponseDto> {
    return this.liquidityMiningService.lockRewardsForGovernance(dto);
  }

  // ═════════════════════════════════════════════════════════════════
  // USER ANALYTICS ENDPOINTS
  // ═════════════════════════════════════════════════════════════════

  /**
   * @route GET /liquidity-mining/user/:userAddress/statistics
   * @desc Get comprehensive liquidity mining statistics for a user
   * @description Returns:
   *   - Total LP provided across all pairs
   *   - Total rewards claimed
   *   - Active stakes
   *   - Recent claimed rewards
   *   - Locked governance power
   */
  @Get('user/:userAddress/statistics')
  @HttpCode(HttpStatus.OK)
  async getUserLiquidityStats(
    @Param('userAddress') userAddress: string
  ): Promise<UserLiquidityStatsDto> {
    return this.liquidityMiningService.getUserLiquidityStats(userAddress);
  }

  /**
   * @route GET /liquidity-mining/health
   * @desc Health check endpoint
   */
  @Get('health')
  @HttpCode(HttpStatus.OK)
  async health(): Promise<{ status: string; timestamp: string }> {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }
}
