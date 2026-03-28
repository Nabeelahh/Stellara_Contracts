import { IsString, IsNumber, IsOptional, Min, Matches, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum SwapChain {
  STELLAR = 'STELLAR',
  ETHEREUM = 'ETHEREUM',
  BITCOIN = 'BITCOIN',
}

export class InitiateSwapDto {
  @ApiProperty({ example: '100.0', description: 'Amount to swap' })
  @IsString()
  amount: string;

  @ApiProperty({ enum: SwapChain, example: SwapChain.ETHEREUM, description: 'Source chain' })
  @IsEnum(SwapChain)
  sourceChain: SwapChain;

  @ApiProperty({ enum: SwapChain, example: SwapChain.STELLAR, description: 'Destination chain' })
  @IsEnum(SwapChain)
  destinationChain: SwapChain;

  @ApiProperty({ example: 'G...ABCD', description: 'Destination wallet address' })
  @IsString()
  destinationAddress: string;

  @ApiProperty({ example: 86400, description: 'Timeout in seconds (default 24h = 86400)' })
  @IsOptional()
  @IsNumber()
  @Min(3600)
  timeoutSeconds?: number = 86400;
}

export class ClaimSwapDto {
  @ApiProperty({ example: 'swap_123', description: 'The unique ID of the swap' })
  @IsString()
  swapId: string;

  @ApiProperty({ example: 'abc123...', description: 'The secret preimage to unlock the assets' })
  @IsString()
  preimage: string;
}

export class RefundSwapDto {
  @ApiProperty({ example: 'swap_123', description: 'The unique ID of the swap' })
  @IsString()
  swapId: string;
}
