import {
  IsString,
  IsOptional,
  IsArray,
  IsEnum,
  IsNumber,
  IsBoolean,
  IsEmail,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PENDING = 'pending',
}

export enum SystemHealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
}

export class UserFilterDto {
  @ApiPropertyOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;

  @ApiPropertyOptional()
  @IsString()
  role?: string;

  @ApiPropertyOptional()
  @IsString()
  tenantId?: string;

  @ApiPropertyOptional()
  @IsString()
  startDate?: string;

  @ApiPropertyOptional()
  @IsString()
  endDate?: string;
}

export class UserManagementDto {
  @ApiPropertyOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;

  @ApiPropertyOptional()
  @IsString()
  role?: string;

  @ApiPropertyOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @ApiPropertyOptional()
  @IsString()
  tenantId?: string;

  @ApiPropertyOptional()
  @IsString()
  notes?: string;
}

export class ImpersonationDto {
  @ApiProperty()
  @IsString()
  targetUserId: string;

  @ApiPropertyOptional()
  @IsString()
  reason?: string;

  @ApiPropertyOptional()
  @IsNumber()
  durationHours?: number = 1;
}

export class SystemMetricsDto {
  @ApiProperty()
  totalUsers: number;

  @ApiProperty()
  activeUsers: number;

  @ApiProperty()
  totalTransactions: number;

  @ApiProperty()
  totalContracts: number;

  @ApiProperty()
  totalWorkflows: number;

  @ApiProperty()
  systemUptime: number;

  @ApiProperty()
  memoryUsage: number;

  @ApiProperty()
  cpuUsage: number;

  @ApiProperty()
  diskUsage: number;

  @ApiProperty()
  databaseConnections: number;

  @ApiProperty()
  cacheHitRate: number;

  @ApiProperty()
  cacheEvictionRate: number;
}

export class TenantUsageDto {
  @ApiProperty()
  tenantId: string;

  @ApiProperty()
  tenantName: string;

  @ApiProperty()
  userCount: number;

  @ApiProperty()
  transactionCount: number;

  @ApiProperty()
  contractCount: number;

  @ApiProperty()
  storageUsed: number;

  @ApiProperty()
  apiCalls: number;

  @ApiProperty()
  lastActivity: Date;
}

export class HealthCheckDto {
  @ApiProperty()
  status: SystemHealthStatus;

  @ApiProperty()
  timestamp: Date;

  @ApiProperty()
  services: Array<{
    name: string;
    status: SystemHealthStatus;
    responseTime: number;
    lastCheck: Date;
    error?: string;
  }>;

  @ApiProperty()
  metrics: {
    uptime: number;
    memoryUsage: number;
    cpuUsage: number;
    activeConnections: number;
  };
}

export class AuditLogQueryDto {
  @ApiPropertyOptional()
  @IsString()
  userId?: string;

  @ApiPropertyOptional()
  @IsString()
  action?: string;

  @ApiPropertyOptional()
  @IsString()
  resource?: string;

  @ApiPropertyOptional()
  @IsString()
  startDate?: string;

  @ApiPropertyOptional()
  @IsString()
  endDate?: string;

  @ApiPropertyOptional()
  @IsNumber()
  @Type(() => Number)
  page?: number = 1;

  @ApiPropertyOptional()
  @IsNumber()
  @Type(() => Number)
  limit?: number = 50;
}

export class ManualOverrideDto {
  @ApiProperty()
  @IsString()
  entityType: string;

  @ApiProperty()
  @IsString()
  entityId: string;

  @ApiProperty()
  @IsString()
  action: string;

  @ApiPropertyOptional()
  @IsObject()
  parameters?: Record<string, any>;

  @ApiProperty()
  @IsString()
  reason: string;

  @ApiPropertyOptional()
  @IsBoolean()
  force?: boolean = false;
}
