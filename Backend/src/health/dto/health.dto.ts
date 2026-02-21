import { ApiProperty } from '@nestjs/swagger';

export class HealthIndicatorDto {
  @ApiProperty({ example: 'database' })
  name: string;

  @ApiProperty({ example: 'up', enum: ['up', 'down', 'degraded', 'unknown'] })
  status: string;

  @ApiProperty({ example: 'Database connection is healthy', required: false })
  message?: string;

  @ApiProperty({ required: false })
  details?: Record<string, any>;

  @ApiProperty({ example: '2026-01-01T00:00:00.000Z', required: false })
  timestamp?: string;
}

export class HealthDto {
  @ApiProperty({ example: 'healthy', enum: ['healthy', 'unhealthy', 'degraded'] })
  status: string;

  @ApiProperty({ example: '2026-01-01T00:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '1.0.0' })
  version: string;

  @ApiProperty({ example: 'production' })
  environment: string;

  @ApiProperty({ example: 3600 })
  uptime: number;

  @ApiProperty({ type: [HealthIndicatorDto] })
  checks: HealthIndicatorDto[];
}

export class HealthSummaryDto extends HealthDto {
  @ApiProperty({
    example: {
      total: 4,
      healthy: 3,
      degraded: 1,
      unhealthy: 0,
    },
    required: false,
  })
  summary?: {
    total: number;
    healthy: number;
    degraded: number;
    unhealthy: number;
  };
}