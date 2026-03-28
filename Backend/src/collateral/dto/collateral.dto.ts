import { IsNotEmpty, IsNumber, IsString, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PledgeCollateralDto {
  @ApiProperty({ example: 'XLM', description: 'Symbol of the asset to pledge' })
  @IsString()
  @IsNotEmpty()
  symbol: string;

  @ApiProperty({ example: 100.5, description: 'Amount of the asset to pledge' })
  @IsNumber()
  @Min(0.0001)
  amount: number;

  @ApiProperty({ example: 'user-id-123', description: 'User ID of the margin account holder' })
  @IsString()
  @IsNotEmpty()
  userId: string;
}

export class SubstitutionDto {
  @ApiProperty({ example: 'XLM', description: 'Symbol of the asset to withdraw' })
  @IsString()
  @IsNotEmpty()
  withdrawSymbol: string;

  @ApiProperty({ example: 100.5, description: 'Amount of the asset to withdraw' })
  @IsNumber()
  @Min(0.0001)
  withdrawAmount: number;

  @ApiProperty({ example: 'BTC', description: 'Symbol of the asset to deposit' })
  @IsString()
  @IsNotEmpty()
  depositSymbol: string;

  @ApiProperty({ example: 0.001, description: 'Amount of the asset to deposit' })
  @IsNumber()
  @Min(0.00000001)
  depositAmount: number;

  @ApiProperty({ example: 'user-id-123', description: 'User ID of the margin account holder' })
  @IsString()
  @IsNotEmpty()
  userId: string;
}

export class LoanRequestDto {
  @ApiProperty({ example: 'USDC', description: 'Symbol of the asset to borrow' })
  @IsString()
  @IsNotEmpty()
  symbol: string;

  @ApiProperty({ example: 50.0, description: 'Amount to borrow' })
  @IsNumber()
  @Min(1.0)
  amount: number;

  @ApiProperty({ example: 'user-id-123', description: 'User ID of the margin account holder' })
  @IsString()
  @IsNotEmpty()
  userId: string;
}
