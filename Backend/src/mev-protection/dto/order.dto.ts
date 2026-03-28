import { IsString, IsNumber, IsEnum, IsOptional, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum OrderType {
  MARKET = 'MARKET',
  LIMIT = 'LIMIT',
  STOP_LOSS = 'STOP_LOSS',
  TAKE_PROFIT = 'TAKE_PROFIT',
}

export enum OrderSide {
  BUY = 'BUY',
  SELL = 'SELL',
}

export enum CommitmentStatus {
  PENDING_COMMIT = 'PENDING_COMMIT',
  COMMITTED = 'COMMITTED',
  REVEALED = 'REVEALED',
  EXECUTED = 'EXECUTED',
  CANCELLED = 'CANCELLED',
  EXPIRED = 'EXPIRED',
}

export class CommitOrderDto {
  @ApiProperty({ description: 'Hash of the order (commitment)' })
  @IsString()
  orderHash: string;

  @ApiProperty({ description: 'User address' })
  @IsString()
  userAddress: string;

  @ApiProperty({ description: 'Order side' })
  @IsEnum(OrderSide)
  side: OrderSide;

  @ApiProperty({ description: 'Trading pair, e.g., XLM/USDC' })
  @IsString()
  pair: string;

  @ApiProperty({ description: 'Order amount' })
  @IsNumber()
  amount: number;

  @ApiProperty({ description: 'Limit price (for limit orders)', required: false })
  @IsOptional()
  @IsNumber()
  price?: number;

  @ApiProperty({ description: 'Order type' })
  @IsEnum(OrderType)
  orderType: OrderType;

  @ApiProperty({ description: 'Slippage tolerance in basis points (e.g., 50 = 0.5%)' })
  @IsNumber()
  maxSlippageBps: number;

  @ApiProperty({ description: 'Expiration timestamp', required: false })
  @IsOptional()
  @IsNumber()
  expiresAt?: number;
}

export class RevealOrderDto {
  @ApiProperty({ description: 'Original order data' })
  @IsString()
  orderData: string;

  @ApiProperty({ description: 'Nonce used in commitment' })
  @IsString()
  nonce: string;

  @ApiProperty({ description: 'Commitment ID' })
  @IsString()
  commitmentId: string;
}

export class ExecuteOrderDto {
  @ApiProperty({ description: 'Commitment ID' })
  @IsString()
  commitmentId: string;

  @ApiProperty({ description: 'DEX routes for execution' })
  @IsString({ each: true })
  dexRoutes: string[];
}

export class MEVProtectionConfig {
  @ApiProperty({ description: 'Enable commit-reveal scheme' })
  @IsBoolean()
  enableCommitReveal: boolean;

  @ApiProperty({ description: 'Enable threshold encryption' })
  @IsBoolean()
  enableThresholdEncryption: boolean;

  @ApiProperty({ description: 'Time window for fair ordering (ms)' })
  @IsNumber()
  fairOrderingWindowMs: number;

  @ApiProperty({ description: 'Minimum delay before reveal (ms)' })
  @IsNumber()
  minRevealDelayMs: number;

  @ApiProperty({ description: 'Maximum slippage protection (bps)' })
  @IsNumber()
  maxSlippageProtectionBps: number;
}
