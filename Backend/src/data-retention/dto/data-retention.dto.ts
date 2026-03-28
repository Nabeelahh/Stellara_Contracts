import { IsBoolean, IsEnum, IsInt, IsNotEmpty, IsOptional, IsString, Max, Min } from 'class-validator';

export enum RetentionDataTypeDto {
  TRADES = 'TRADES',
  LOGS = 'LOGS',
  SESSIONS = 'SESSIONS',
  ANALYTICS = 'ANALYTICS',
  WEBHOOKS = 'WEBHOOKS',
  AUDIT = 'AUDIT',
}

export class CreateRetentionRuleDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEnum(RetentionDataTypeDto)
  dataType: RetentionDataTypeDto;

  @IsOptional()
  @IsString()
  tenantId?: string;

  @IsInt()
  @Min(1)
  @Max(3650)
  retentionDays: number;

  @IsOptional()
  @IsBoolean()
  archiveEnabled?: boolean = true;

  @IsOptional()
  @IsString()
  archivePrefix?: string;

  @IsOptional()
  @IsBoolean()
  secureDelete?: boolean = true;

  @IsOptional()
  @IsBoolean()
  legalHoldEnabled?: boolean = true;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean = true;
}

export class UpdateRetentionRuleDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(3650)
  retentionDays?: number;

  @IsOptional()
  @IsBoolean()
  archiveEnabled?: boolean;

  @IsOptional()
  @IsString()
  archivePrefix?: string;

  @IsOptional()
  @IsBoolean()
  secureDelete?: boolean;

  @IsOptional()
  @IsBoolean()
  legalHoldEnabled?: boolean;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class CreateLegalHoldDto {
  @IsEnum(RetentionDataTypeDto)
  dataType: RetentionDataTypeDto;

  @IsString()
  @IsNotEmpty()
  referenceId: string;

  @IsString()
  @IsNotEmpty()
  reason: string;

  @IsOptional()
  @IsString()
  heldBy?: string;

  @IsOptional()
  @IsString()
  expiresAt?: string;

  @IsOptional()
  metadata?: Record<string, unknown>;
}

export class ExecuteRetentionDto {
  @IsOptional()
  @IsBoolean()
  dryRun?: boolean = false;
}

export class ForgetUserDto {
  @IsString()
  @IsNotEmpty()
  requestedBy: string;

  @IsOptional()
  @IsString()
  reason?: string;
}

