import { IsString, IsOptional, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ActionType } from '@prisma/client';

export class CreateSupportActionDto {
  @ApiProperty({ description: 'User ID the action is performed on' })
  @IsString()
  userId: string;

  @ApiProperty({ enum: ActionType, description: 'Type of action' })
  @IsEnum(ActionType)
  actionType: ActionType;

  @ApiProperty({ description: 'Action description' })
  @IsString()
  description: string;

  @ApiPropertyOptional({ description: 'Additional metadata' })
  @IsOptional()
  metadata?: Record<string, any>;
}

export class ImpersonateUserDto {
  @ApiProperty({ description: 'User ID to impersonate' })
  @IsString()
  userId: string;

  @ApiPropertyOptional({ description: 'Reason for impersonation' })
  @IsOptional()
  @IsString()
  reason?: string;
}
