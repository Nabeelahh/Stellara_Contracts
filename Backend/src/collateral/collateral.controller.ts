import { Controller, Post, Body, Get, Param, UseGuards, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CollateralService } from './collateral.service';
import { LiquidationService } from './liquidation.service';
import { PledgeCollateralDto, SubstitutionDto, LoanRequestDto } from './dto/collateral.dto';

@ApiTags('Collateral Management')
@Controller('collateral')
export class CollateralController {
  constructor(
    private readonly collateralService: CollateralService,
    private readonly liquidationService: LiquidationService,
  ) {}

  @Post('seed')
  @ApiOperation({ summary: 'Seed default collateral assets' })
  async seedAssets() {
    await this.collateralService.seedDefaultAssets();
    return { message: 'Default assets seeded successfully' };
  }

  @Post('pledge')
  @ApiOperation({ summary: 'Pledge collateral to a margin account' })
  @ApiResponse({ status: 201, description: 'Collateral pledged successfully' })
  async pledgeCollateral(@Body() dto: PledgeCollateralDto) {
    return this.collateralService.pledgeCollateral(dto);
  }

  @Post('substitute')
  @ApiOperation({ summary: 'Substitute collateral (withdraw one asset and deposit another)' })
  async substituteCollateral(@Body() dto: SubstitutionDto) {
    return this.collateralService.substituteCollateral(dto);
  }

  @Post('loan')
  @ApiOperation({ summary: 'Request a loan against pledged collateral' })
  async requestLoan(@Body() dto: LoanRequestDto) {
    return this.collateralService.requestLoan(dto);
  }

  @Get('health/:userId')
  @ApiOperation({ summary: 'Get margin account health and LTV' })
  async getAccountHealth(@Param('userId') userId: string) {
    return this.collateralService.calculateAccountHealth(userId);
  }

  @Post('liquidate/:userId')
  @ApiOperation({ summary: 'Manually trigger liquidation for an eligible account' })
  async triggerLiquidation(
    @Param('userId') userId: string,
    @Body('liquidatorAddress') liquidatorAddress: string,
    @Query('partial') partial: boolean = true,
  ) {
    return this.liquidationService.liquidateAccount(userId, liquidatorAddress, partial);
  }
}
