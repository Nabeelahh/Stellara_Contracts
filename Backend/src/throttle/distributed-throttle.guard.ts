/**
 * Enhanced Distributed Throttle Guard
 * Implements distributed rate limiting with role-based configuration
 */

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import {
  DistributedRateLimitService,
  RateLimitStrategyType,
  RateLimitIdentifier,
} from './distributed-rate-limit.service';
import {
  RoleBasedRateLimitService,
  EndpointCategory,
  UserRole,
} from './role-based-rate-limit.service';

/**
 * Metadata for rate limit configuration on endpoints
 */
export interface RateLimitMetadata {
  category?: EndpointCategory;
  skipRoles?: UserRole[];
  custom?: string;
  strategy?: RateLimitStrategyType;
}

/**
 * Enhanced throttle guard with distributed rate limiting
 */
@Injectable()
export class DistributedThrottleGuard implements CanActivate {
  constructor(
    private readonly distributedRateLimiter: DistributedRateLimitService,
    private readonly roleBasedRateLimiter: RoleBasedRateLimitService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    try {
      // Extract metadata from handler
      const handler = context.getHandler();
      const metadata: RateLimitMetadata = Reflect.getMetadata(
        'rate-limit',
        handler,
      ) || {
        category: EndpointCategory.PUBLIC,
      };

      // Get user information
      const userId = (request as any).user?.id;
      const userRole = (request as any).user?.role || UserRole.ANONYMOUS;

      // Check if role should skip rate limiting
      if (metadata.skipRoles?.includes(userRole)) {
        return true;
      }

      // Get client IP
      const ip =
        (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
        request.socket.remoteAddress ||
        'unknown';

      // Build rate limit identifier
      const identifier: RateLimitIdentifier = {
        ip,
        userId,
        path: request.path,
        custom: metadata.custom,
      };

      // Check if identifier is banned
      const isBanned = await this.distributedRateLimiter.isBanned(identifier);
      if (isBanned) {
        response.setHeader('Retry-After', '3600');
        throw new HttpException(
          'Temporarily banned due to rate limit violations',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      // Get rate limit configuration
      const config = this.roleBasedRateLimiter.getRateLimit(
        userRole,
        metadata.category,
      );

      // Check endpoint access
      if (config.limit === 0) {
        throw new HttpException(
          'Access denied for your role',
          HttpStatus.FORBIDDEN,
        );
      }

      // Check rate limit
      const strategy =
        metadata.strategy || RateLimitStrategyType.SLIDING_WINDOW_COUNTER;
      const result = await this.distributedRateLimiter.checkRateLimit(
        identifier,
        config,
        strategy,
      );

      // Set rate limit headers
      response.setHeader('X-RateLimit-Limit', result.limit);
      response.setHeader('X-RateLimit-Remaining', result.remaining);
      response.setHeader('X-RateLimit-Reset', result.resetTime);

      if (!result.allowed) {
        response.setHeader('Retry-After', result.resetIn);

        // Record violation and check for ban
        await this.handleViolation(identifier, config);

        throw new HttpException(
          `Rate limit exceeded. Retry after ${result.resetIn} seconds`,
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      return true;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }

      // Log unexpected errors but allow request
      console.error('Rate limiting error:', error);
      return true;
    }
  }

  /**
   * Handle rate limit violation
   */
  private async handleViolation(
    identifier: RateLimitIdentifier,
    config: any,
  ): Promise<void> {
    const metrics = await this.distributedRateLimiter.getMetrics(identifier);

    // Auto-ban after excessive violations
    const MAX_VIOLATIONS = 10;
    if (metrics.violations >= MAX_VIOLATIONS) {
      const banDuration = Math.min(3600, 60 * Math.pow(2, metrics.violations - MAX_VIOLATIONS));
      await this.distributedRateLimiter.banIdentifier(
        identifier,
        banDuration,
      );
    }
  }
}
