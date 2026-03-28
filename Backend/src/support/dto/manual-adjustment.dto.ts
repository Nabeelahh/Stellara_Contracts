import { IsString, IsOptional, IsEnum, IsNumber, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AdjustmentType } from '@prisma/client';

export class CreateManualAdjustmentDto {
  @ApiProperty({ description: 'User ID to adjust' })
  @IsString()
  userId: string;

  @ApiProperty({ enum: AdjustmentType, description: 'Type of adjustment' })
  @IsEnum(AdjustmentType)
  adjustmentType: AdjustmentType;

  @ApiProperty({ description: 'Adjustment amount' })
  @IsNumber()
  amount: number;

  @ApiPropertyOptional({ description: 'Currency (default: USD)' })
  @IsOptional()
  @IsString()
  currency?: string;

  @ApiProperty({ description: 'Reason for adjustment' })
  @IsString()
  reason: string;

  @ApiPropertyOptional({ description: 'Reference ID for related transaction' })
  @IsOptional()
  @IsString()
  referenceId?: string;

  @ApiPropertyOptional({ description: 'Reference type (e.g., contribution, claim)' })
  @IsOptional()
  @IsString()
  referenceType?: string;
}

export class ApproveAdjustmentDto {
  @ApiProperty({ description: 'Adjustment ID to approve' })
  @IsUUID()
  adjustmentId: string;

  @ApiPropertyOptional({ description: 'Approval notes' })
  @IsOptional()
  @IsString()
  notes?: string;
}

export class RejectAdjustmentDto {
  @ApiProperty({ description: 'Adjustment ID to reject' })
  @IsUUID()
  adjustmentId: string;

  @ApiProperty({ description: 'Rejection reason' })
  @IsString()
  reason: string;
}
