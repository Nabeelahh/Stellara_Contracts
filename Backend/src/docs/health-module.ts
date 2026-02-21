import { Controller, Get, Module } from '@nestjs/common';
import { ApiTags, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { ApiProperty } from '@nestjs/swagger';

// ─── Response DTO ─────────────────────────────────────────────────────────────

export class HealthDto {
  @ApiProperty({ example: 'ok' })
  status: string;

  @ApiProperty({ example: '2026-01-01T00:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '1.0.0' })
  version: string;

  @ApiProperty({ example: 'production' })
  environment: string;
}

// ─── Controller ───────────────────────────────────────────────────────────────

@ApiTags('Health')
@Controller('health')
export class HealthController {
  @Get()
  @ApiOperation({ summary: 'Liveness probe — confirms the server is running' })
  @ApiOkResponse({ type: HealthDto, description: 'Server is alive' })
  check(): HealthDto {
    return {
      status:      'ok',
      timestamp:   new Date().toISOString(),
      version:     process.env.npm_package_version ?? '1.0.0',
      environment: process.env.NODE_ENV ?? 'development',
    };
  }
}

// ─── Module ───────────────────────────────────────────────────────────────────

@Module({ controllers: [HealthController] })
export class HealthModule {}