import {
  IsString,
  IsBoolean,
  IsOptional,
  IsEnum,
  IsInt,
  Min,
  Max,
  IsObject,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ConfigScope } from '../interfaces/config.interfaces';

export class SetConfigDto {
  @ApiProperty({
    description: 'Configuration key name',
    example: 'maxUploadSize',
  })
  @IsString()
  key: string;

  @ApiProperty({
    description: 'Configuration value (string representation)',
    example: '10485760',
  })
  @IsString()
  value: string;

  @ApiPropertyOptional({
    description: 'Scope of the configuration',
    enum: ConfigScope,
    example: ConfigScope.GLOBAL,
  })
  @IsEnum(ConfigScope)
  @IsOptional()
  scope?: ConfigScope;

  @ApiPropertyOptional({
    description: 'Tenant ID for tenant-scoped configuration',
    example: 'tenant_123',
  })
  @IsString()
  @IsOptional()
  tenantId?: string;

  @ApiPropertyOptional({
    description: 'User ID for user-scoped configuration',
    example: 'user_456',
  })
  @IsString()
  @IsOptional()
  userId?: string;

  @ApiPropertyOptional({
    description: 'Whether the value should be encrypted at rest',
    example: false,
  })
  @IsBoolean()
  @IsOptional()
  encrypted?: boolean;
}

export class SetFeatureFlagDto {
  @ApiProperty({
    description: 'Feature flag key name',
    example: 'newDashboard',
  })
  @IsString()
  key: string;

  @ApiProperty({
    description: 'Whether the feature flag is enabled',
    example: true,
  })
  @IsBoolean()
  enabled: boolean;

  @ApiPropertyOptional({
    description: 'Tenant ID for tenant-scoped feature flag',
    example: 'tenant_123',
  })
  @IsString()
  @IsOptional()
  tenantId?: string;

  @ApiPropertyOptional({
    description: 'Rollout percentage (0-100)',
    example: 50,
    minimum: 0,
    maximum: 100,
  })
  @IsInt()
  @Min(0)
  @Max(100)
  @IsOptional()
  rolloutPct?: number;

  @ApiPropertyOptional({
    description: 'Additional metadata for the feature flag',
    example: { description: 'Enable new dashboard UI', owner: 'frontend-team' },
  })
  @IsObject()
  @IsOptional()
  metadata?: Record<string, unknown>;
}

export class GetConfigDto {
  @ApiProperty({
    description: 'Configuration key to retrieve',
    example: 'maxUploadSize',
  })
  @IsString()
  key: string;

  @ApiPropertyOptional({
    description: 'Tenant ID for tenant-scoped configuration',
    example: 'tenant_123',
  })
  @IsString()
  @IsOptional()
  tenantId?: string;

  @ApiPropertyOptional({
    description: 'User ID for user-scoped configuration',
    example: 'user_456',
  })
  @IsString()
  @IsOptional()
  userId?: string;
}
