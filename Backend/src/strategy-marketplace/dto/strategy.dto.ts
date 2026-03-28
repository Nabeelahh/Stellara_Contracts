import { IsString, IsNumber, IsEnum, IsOptional, IsBoolean, IsObject } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum StrategyType {
  MARKET_MAKING = 'MARKET_MAKING',
  ARBITRAGE = 'ARBITRAGE',
  TREND_FOLLOWING = 'TREND_FOLLOWING',
  MEAN_REVERSION = 'MEAN_REVERSION',
  STATISTICAL = 'STATISTICAL',
}

export enum PricingModel {
  ONE_TIME = 'ONE_TIME',
  SUBSCRIPTION = 'SUBSCRIPTION',
  PROFIT_SHARE = 'PROFIT_SHARE',
  FREE = 'FREE',
}

export enum RiskLevel {
  CONSERVATIVE = 'CONSERVATIVE',
  MODERATE = 'MODERATE',
  AGGRESSIVE = 'AGGRESSIVE',
  VERY_AGGRESSIVE = 'VERY_AGGRESSIVE',
}

export class SubmitStrategyDto {
  @ApiProperty({ description: 'Strategy name' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'Strategy description' })
  @IsString()
  description: string;

  @ApiProperty({ description: 'Strategy type' })
  @IsEnum(StrategyType)
  strategyType: StrategyType;

  @ApiProperty({ description: 'Docker image or WASM module URL' })
  @IsString()
  executionModule: string;

  @ApiProperty({ description: 'Risk level' })
  @IsEnum(RiskLevel)
  riskLevel: RiskLevel;

  @ApiProperty({ description: 'Pricing model' })
  @IsEnum(PricingModel)
  pricingModel: PricingModel;

  @ApiProperty({ description: 'Price in USD cents', required: false })
  @IsOptional()
  @IsNumber()
  priceUsdCents?: number;

  @ApiProperty({ description: 'Profit share percentage (0-100)', required: false })
  @IsOptional()
  @IsNumber()
  profitSharePercent?: number;

  @ApiProperty({ description: 'Max position size in USD', required: false })
  @IsOptional()
  @IsNumber()
  maxPositionSize?: number;

  @ApiProperty({ description: 'Stop loss percentage', required: false })
  @IsOptional()
  @IsNumber()
  stopLossPercent?: number;

  @ApiProperty({ description: 'Target assets/trading pairs' })
  @IsString({ each: true })
  supportedPairs: string[];
}

export class BacktestRequestDto {
  @ApiProperty({ description: 'Strategy ID or execution module' })
  @IsString()
  strategyId: string;

  @ApiProperty({ description: 'Start date for backtesting' })
  @IsString()
  startDate: string;

  @ApiProperty({ description: 'End date for backtesting' })
  @IsString()
  endDate: string;

  @ApiProperty({ description: 'Initial capital in USD' })
  @IsNumber()
  initialCapital: number;

  @ApiProperty({ description: 'Trading pairs to test', required: false })
  @IsOptional()
  @IsString({ each: true })
  pairs?: string[];
}

export class CopyTradeDto {
  @ApiProperty({ description: 'Strategy ID to copy' })
  @IsString()
  strategyId: string;

  @ApiProperty({ description: 'Amount to allocate in USD' })
  @IsNumber()
  allocationAmount: number;

  @ApiProperty({ description: 'Maximum allocation (risk control)' })
  @IsOptional()
  @IsNumber()
  maxAllocation?: number;

  @ApiProperty({ description: 'User-defined stop loss override' })
  @IsOptional()
  @IsNumber()
  stopLossOverride?: number;
}
