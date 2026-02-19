/**
 * Role-Based Rate Limiting Configuration
 * Provides dynamic rate limits based on user roles
 */

import { Injectable, Logger } from '@nestjs/common';
import { RateLimitConfig } from './rate-limit-strategies';

/**
 * User role enumeration
 */
export enum UserRole {
  ANONYMOUS = 'anonymous',
  USER = 'user',
  PREMIUM = 'premium',
  ADMIN = 'admin',
  SYSTEM = 'system',
}

/**
 * Endpoint category for different rate limit tiers
 */
export enum EndpointCategory {
  AUTH = 'auth',
  PUBLIC = 'public',
  MARKET_DATA = 'market-data',
  TRADING = 'trading',
  WEBHOOK = 'webhook',
  AI = 'ai',
  ADMIN = 'admin',
}

/**
 * Rate limit tier configuration
 */
interface RateLimitTier {
  roles: UserRole[];
  limits: Record<EndpointCategory, RateLimitConfig>;
}

/**
 * Role-based rate limit service
 */
@Injectable()
export class RoleBasedRateLimitService {
  private readonly logger = new Logger('RoleBasedRateLimiter');

  /**
   * Rate limit tiers for different user roles
   */
  private readonly rateLimitTiers: RateLimitTier[] = [
    {
      roles: [UserRole.SYSTEM],
      limits: {
        [EndpointCategory.AUTH]: { limit: 1000, window: 60 },
        [EndpointCategory.PUBLIC]: { limit: 10000, window: 60 },
        [EndpointCategory.MARKET_DATA]: { limit: 10000, window: 60 },
        [EndpointCategory.TRADING]: { limit: 5000, window: 60 },
        [EndpointCategory.WEBHOOK]: { limit: 10000, window: 60 },
        [EndpointCategory.AI]: { limit: 5000, window: 60 },
        [EndpointCategory.ADMIN]: { limit: 10000, window: 60 },
      },
    },
    {
      roles: [UserRole.ADMIN],
      limits: {
        [EndpointCategory.AUTH]: { limit: 500, window: 60 },
        [EndpointCategory.PUBLIC]: { limit: 5000, window: 60 },
        [EndpointCategory.MARKET_DATA]: { limit: 2000, window: 60 },
        [EndpointCategory.TRADING]: { limit: 1000, window: 60 },
        [EndpointCategory.WEBHOOK]: { limit: 500, window: 60 },
        [EndpointCategory.AI]: { limit: 500, window: 60 },
        [EndpointCategory.ADMIN]: { limit: 5000, window: 60 },
      },
    },
    {
      roles: [UserRole.PREMIUM],
      limits: {
        [EndpointCategory.AUTH]: { limit: 100, window: 60 },
        [EndpointCategory.PUBLIC]: { limit: 1000, window: 60 },
        [EndpointCategory.MARKET_DATA]: { limit: 500, window: 60 },
        [EndpointCategory.TRADING]: { limit: 300, window: 60 },
        [EndpointCategory.WEBHOOK]: { limit: 200, window: 60 },
        [EndpointCategory.AI]: { limit: 100, window: 60 },
        [EndpointCategory.ADMIN]: { limit: 50, window: 60 },
      },
    },
    {
      roles: [UserRole.USER],
      limits: {
        [EndpointCategory.AUTH]: { limit: 50, window: 60 },
        [EndpointCategory.PUBLIC]: { limit: 500, window: 60 },
        [EndpointCategory.MARKET_DATA]: { limit: 300, window: 60 },
        [EndpointCategory.TRADING]: { limit: 100, window: 60 },
        [EndpointCategory.WEBHOOK]: { limit: 50, window: 60 },
        [EndpointCategory.AI]: { limit: 20, window: 60 },
        [EndpointCategory.ADMIN]: { limit: 0, window: 60 },
      },
    },
    {
      roles: [UserRole.ANONYMOUS],
      limits: {
        [EndpointCategory.AUTH]: { limit: 10, window: 60 },
        [EndpointCategory.PUBLIC]: { limit: 100, window: 60 },
        [EndpointCategory.MARKET_DATA]: { limit: 50, window: 60 },
        [EndpointCategory.TRADING]: { limit: 0, window: 60 },
        [EndpointCategory.WEBHOOK]: { limit: 0, window: 60 },
        [EndpointCategory.AI]: { limit: 0, window: 60 },
        [EndpointCategory.ADMIN]: { limit: 0, window: 60 },
      },
    },
  ];

  /**
   * Get rate limit configuration for user role and endpoint
   */
  getRateLimit(
    role: UserRole | string = UserRole.ANONYMOUS,
    category: EndpointCategory | string = EndpointCategory.PUBLIC,
  ): RateLimitConfig {
    // Normalize role
    const normalizedRole = this.normalizeRole(role);

    // Find tier for role
    const tier = this.rateLimitTiers.find((t) =>
      t.roles.includes(normalizedRole),
    );

    if (!tier) {
      this.logger.warn(`No rate limit tier found for role: ${role}`);
      return this.rateLimitTiers[
        this.rateLimitTiers.length - 1
      ].limits[EndpointCategory.PUBLIC];
    }

    // Get limit for category
    const categoryKey = this.normalizeCategory(category);
    const limit = tier.limits[categoryKey] || tier.limits[EndpointCategory.PUBLIC];

    return limit;
  }

  /**
   * Get all rate limits for a specific role
   */
  getAllLimitsForRole(role: UserRole | string): Record<EndpointCategory, RateLimitConfig> {
    const normalizedRole = this.normalizeRole(role);
    const tier = this.rateLimitTiers.find((t) =>
      t.roles.includes(normalizedRole),
    );

    if (!tier) {
      return this.rateLimitTiers[this.rateLimitTiers.length - 1].limits;
    }

    return tier.limits;
  }

  /**
   * Update rate limit for specific role and category
   */
  updateRateLimit(
    role: UserRole | string,
    category: EndpointCategory | string,
    config: RateLimitConfig,
  ): void {
    const normalizedRole = this.normalizeRole(role);
    const categoryKey = this.normalizeCategory(category);

    const tier = this.rateLimitTiers.find((t) =>
      t.roles.includes(normalizedRole),
    );

    if (!tier) {
      this.logger.error(`Cannot update rate limit: role not found: ${role}`);
      return;
    }

    tier.limits[categoryKey] = config;
    this.logger.log(
      `Updated rate limit: Role=${role}, Category=${category}, Limit=${config.limit}/${config.window}s`,
    );
  }

  /**
   * Add custom rate limit tier
   */
  addCustomTier(
    roleName: string,
    limits: Record<EndpointCategory, RateLimitConfig>,
  ): void {
    const existingTier = this.rateLimitTiers.find((t) =>
      t.roles.includes(roleName as UserRole),
    );

    if (existingTier) {
      this.logger.warn(`Custom tier already exists for role: ${roleName}`);
      return;
    }

    this.rateLimitTiers.push({
      roles: [roleName as UserRole],
      limits,
    });

    this.logger.log(`Added custom rate limit tier for role: ${roleName}`);
  }

  /**
   * Check if user has access to endpoint category
   */
  canAccessEndpoint(
    role: UserRole | string,
    category: EndpointCategory | string,
  ): boolean {
    const limit = this.getRateLimit(role, category);
    return limit.limit > 0;
  }

  /**
   * Get rate limit summary for all roles
   */
  getSummary(): Record<string, Record<string, RateLimitConfig>> {
    const summary: Record<string, Record<string, RateLimitConfig>> = {};

    for (const tier of this.rateLimitTiers) {
      for (const role of tier.roles) {
        summary[role] = tier.limits;
      }
    }

    return summary;
  }

  /**
   * Normalize role to enum
   */
  private normalizeRole(role: string | UserRole): UserRole {
    const roleStr = String(role).toLowerCase();
    return (Object.values(UserRole).find(
      (r) => r === roleStr,
    ) || UserRole.ANONYMOUS) as UserRole;
  }

  /**
   * Normalize category to enum
   */
  private normalizeCategory(category: string | EndpointCategory): EndpointCategory {
    const categoryStr = String(category).toLowerCase().replace(/-/g, '_');
    return (Object.values(EndpointCategory).find(
      (c) => c === categoryStr,
    ) || EndpointCategory.PUBLIC) as EndpointCategory;
  }
}
