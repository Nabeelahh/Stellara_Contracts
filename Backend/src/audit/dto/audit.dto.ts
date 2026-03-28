import { IsDateString, IsEnum, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';
import { Transform, Type } from 'class-transformer';

import { AuditAction } from '@prisma/client';

export class QueryAuditLogsDto {
  @IsOptional()
  @IsString()
  tenantId?: string;

  @IsOptional()
  @IsString()
  userId?: string;

  @IsOptional()
  @IsString()
  entityType?: string;

  @IsOptional()
  @IsString()
  entityId?: string;

  @IsOptional()
  @IsEnum(AuditAction)
  action?: AuditAction;

  @IsOptional()
  @IsString()
  correlationId?: string;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsInt()
  @Type(() => Number)
  statusCode?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  page?: number = 1;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 50;

  @IsOptional()
  @IsEnum(['createdAt', 'action', 'entityType'])
  sortBy?: 'createdAt' | 'action' | 'entityType' = 'createdAt';

  @IsOptional()
  @IsEnum(['asc', 'desc'])
  sortOrder?: 'asc' | 'desc' = 'desc';
}

export class GetEntityHistoryDto {
  @IsString()
  entityType: string;

  @IsString()
  entityId: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  page?: number = 1;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 50;
}

export class GetStatisticsDto {
  @IsDateString()
  startDate: string;

  @IsDateString()
  endDate: string;

  @IsOptional()
  @IsString()
  tenantId?: string;
}

export class CreateRetentionPolicyDto {
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  tenantId?: string;

  @IsInt()
  @Min(1)
  @Max(3650) // Maximum 10 years
  retentionDays: number;

  @IsOptional()
  @IsString({ each: true })
  entityTypes?: string[];

  @IsOptional()
  @IsEnum(AuditAction, { each: true })
  actions?: AuditAction[];

  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  archiveEnabled?: boolean = false;

  @IsOptional()
  @IsString()
  archiveLocation?: string;
}

export class UpdateRetentionPolicyDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(3650)
  retentionDays?: number;

  @IsOptional()
  @IsString({ each: true })
  entityTypes?: string[];

  @IsOptional()
  @IsEnum(AuditAction, { each: true })
  actions?: AuditAction[];

  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  archiveEnabled?: boolean;

  @IsOptional()
  @IsString()
  archiveLocation?: string;

  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  isActive?: boolean;
}
