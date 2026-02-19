/**
 * Rate Limiting Management Controller
 * Admin endpoints for monitoring and managing rate limits
 */

import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Query,
  Body,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { RolesGuard } from '../auth/guards/roles.guard';
import { RolesDecorator } from '../decorators/roles.decorator';
import { DistributedRateLimitService, RateLimitIdentifier } from './distributed-rate-limit.service';
import { RoleBasedRateLimitService, EndpointCategory, UserRole } from './role-based-rate-limit.service';
import { RateLimitMetricsCollector } from './rate-limit-metrics.collector';
import { RateLimitConfig } from './rate-limit-strategies';

@ApiTags('Rate Limiting Management')
@Controller('api/admin/rate-limits')
@UseGuards(RolesGuard)
@RolesDecorator([UserRole.ADMIN, UserRole.SYSTEM])
export class RateLimitingController {
  constructor(
    private readonly rateLimitService: DistributedRateLimitService,
    private readonly roleBasedService: RoleBasedRateLimitService,
    private readonly metricsCollector: RateLimitMetricsCollector,
  ) {}

  /**
   * Get system-wide rate limiting statistics
   */
  @Get('metrics')
  @ApiOperation({ summary: 'Get system-wide rate limit metrics' })
  @ApiResponse({
    status: 200,
    description: 'System rate limit metrics',
  })
  async getMetrics() {
    return this.metricsCollector.getCurrentMetrics();
  }

  /**
   * Get Prometheus metrics
   */
  @Get('metrics/prometheus')
  @ApiOperation({ summary: 'Get Prometheus format metrics' })
  @ApiResponse({
    status: 200,
    description: 'Prometheus metrics in text format',
  })
  async getPrometheusMetrics() {
    return this.metricsCollector.getPrometheusMetrics();
  }

  /**
   * Get rate limit configuration for a role
   */
  @Get('config/:role')
  @ApiOperation({ summary: 'Get rate limit configuration for a user role' })
  @ApiResponse({
    status: 200,
    description: 'Rate limit configuration for role',
  })
  async getConfigForRole(@Param('role') role: UserRole) {
    return this.roleBasedService.getAllLimitsForRole(role);
  }

  /**
   * Get all rate limit configurations
   */
  @Get('config')
  @ApiOperation({ summary: 'Get all rate limit configurations' })
  @ApiResponse({
    status: 200,
    description: 'All rate limit configurations by role',
  })
  async getAllConfigs() {
    return this.roleBasedService.getSummary();
  }

  /**
   * Update rate limit for a role and category
   */
  @Post('config')
  @HttpCode(200)
  @ApiOperation({ summary: 'Update rate limit configuration' })
  @ApiResponse({
    status: 200,
    description: 'Rate limit configuration updated',
  })
  async updateConfig(
    @Body()
    body: {
      role: UserRole;
      category: EndpointCategory;
      limit: number;
      window: number;
    },
  ) {
    this.roleBasedService.updateRateLimit(body.role, body.category, {
      limit: body.limit,
      window: body.window,
    });

    return {
      success: true,
      message: `Updated rate limit for ${body.role} on ${body.category}`,
    };
  }

  /**
   * Get rate limit metrics for an identifier
   */
  @Get('identifier/:ip')
  @ApiOperation({ summary: 'Get rate limit metrics for an IP address' })
  @ApiResponse({
    status: 200,
    description: 'Rate limit metrics for identifier',
  })
  async getIdentifierMetrics(
    @Param('ip') ip: string,
    @Query('userId') userId?: string,
  ) {
    const identifier: RateLimitIdentifier = {
      ip,
      userId,
      path: '/',
    };

    return this.rateLimitService.getMetrics(identifier);
  }

  /**
   * Ban an identifier
   */
  @Post('ban')
  @HttpCode(200)
  @ApiOperation({ summary: 'Ban an IP address or user' })
  @ApiResponse({
    status: 200,
    description: 'Identifier banned successfully',
  })
  async banIdentifier(
    @Body()
    body: {
      ip: string;
      userId?: string;
      durationSeconds: number;
    },
  ) {
    const identifier: RateLimitIdentifier = {
      ip: body.ip,
      userId: body.userId,
      path: '/',
    };

    await this.rateLimitService.banIdentifier(
      identifier,
      body.durationSeconds,
    );

    return {
      success: true,
      message: `Banned ${body.ip} for ${body.durationSeconds} seconds`,
    };
  }

  /**
   * Unban an identifier
   */
  @Delete('ban/:ip')
  @ApiOperation({ summary: 'Unban an IP address' })
  @ApiResponse({
    status: 200,
    description: 'Identifier unbanned successfully',
  })
  async unbanIdentifier(@Param('ip') ip: string, @Query('userId') userId?: string) {
    const identifier: RateLimitIdentifier = {
      ip,
      userId,
      path: '/',
    };

    await this.rateLimitService.unbanIdentifier(identifier);

    return {
      success: true,
      message: `Unbanned ${ip}`,
    };
  }

  /**
   * Reset rate limit for identifier
   */
  @Delete('identifier/:ip')
  @ApiOperation({ summary: 'Reset rate limit for an identifier' })
  @ApiResponse({
    status: 200,
    description: 'Rate limit reset successfully',
  })
  async resetIdentifier(@Param('ip') ip: string, @Query('userId') userId?: string) {
    const identifier: RateLimitIdentifier = {
      ip,
      userId,
      path: '/',
    };

    await this.rateLimitService.resetRateLimit(identifier);

    return {
      success: true,
      message: `Reset rate limit for ${ip}`,
    };
  }

  /**
   * Get active rate limit keys
   */
  @Get('keys')
  @ApiOperation({ summary: 'Get list of active rate limit keys' })
  @ApiResponse({
    status: 200,
    description: 'List of active keys',
  })
  async getActiveKeys(@Query('pattern') pattern?: string) {
    const keys = await this.rateLimitService.getActiveKeys();
    const filtered = pattern ? keys.filter((k) => k.includes(pattern)) : keys;

    return {
      total: filtered.length,
      keys: filtered.slice(0, 100), // Limit to first 100
    };
  }

  /**
   * Check if endpoint category is accessible for role
   */
  @Get('access/:role/:category')
  @ApiOperation({ summary: 'Check if role has access to endpoint category' })
  @ApiResponse({
    status: 200,
    description: 'Access check result',
  })
  async checkAccess(
    @Param('role') role: UserRole,
    @Param('category') category: EndpointCategory,
  ) {
    const canAccess = this.roleBasedService.canAccessEndpoint(role, category);
    const limit = this.roleBasedService.getRateLimit(role, category);

    return {
      role,
      category,
      canAccess,
      limit: limit.limit,
      window: limit.window,
    };
  }

  /**
   * Reset all rate limits matching pattern
   */
  @Delete('reset-all')
  @HttpCode(200)
  @ApiOperation({ summary: 'Reset all rate limits matching pattern' })
  @ApiResponse({
    status: 200,
    description: 'All matching rate limits reset',
  })
  async resetAll(@Query('pattern') pattern: string) {
    if (!pattern) {
      throw new Error('Pattern is required');
    }

    await this.rateLimitService.resetAllRateLimits(pattern);

    return {
      success: true,
      message: `Reset all rate limits matching pattern: ${pattern}`,
    };
  }
}
