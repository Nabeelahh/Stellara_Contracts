/**
 * Rate Limiting Configuration
 * Centralized configuration for distributed rate limiting
 */

import { RateLimitConfig } from './rate-limit-strategies';
import { EndpointCategory, UserRole } from './role-based-rate-limit.service';

/**
 * Default rate limit configurations by endpoint category
 */
export const DEFAULT_RATE_LIMITS: Record<EndpointCategory, RateLimitConfig> = {
  [EndpointCategory.AUTH]: { limit: 10, window: 60 },
  [EndpointCategory.PUBLIC]: { limit: 100, window: 60 },
  [EndpointCategory.MARKET_DATA]: { limit: 300, window: 60 },
  [EndpointCategory.TRADING]: { limit: 100, window: 60 },
  [EndpointCategory.WEBHOOK]: { limit: 200, window: 60 },
  [EndpointCategory.AI]: { limit: 50, window: 60 },
  [EndpointCategory.ADMIN]: { limit: 500, window: 60 },
};

/**
 * Role-specific multipliers for rate limits
 * Applied to default limits
 */
export const ROLE_MULTIPLIERS: Record<UserRole, number> = {
  [UserRole.SYSTEM]: 100, // No real limit
  [UserRole.ADMIN]: 5, // 5x default
  [UserRole.PREMIUM]: 2, // 2x default
  [UserRole.USER]: 1, // Default limit
  [UserRole.ANONYMOUS]: 0.1, // 10% of default
};

/**
 * Ban configuration
 */
export const BAN_CONFIG = {
  // Maximum violations before automatic ban
  MAX_VIOLATIONS_BEFORE_BAN: 10,

  // Base ban duration in seconds
  BASE_BAN_DURATION: 300, // 5 minutes

  // Maximum ban duration
  MAX_BAN_DURATION: 86400, // 24 hours

  // Exponential backoff multiplier
  BAN_BACKOFF_MULTIPLIER: 2,
};

/**
 * Monitoring configuration
 */
export const MONITORING_CONFIG = {
  // Metrics update interval (ms)
  METRICS_UPDATE_INTERVAL: 10000, // 10 seconds

  // Violation log retention (entries)
  VIOLATION_LOG_RETENTION: 100,

  // Enable detailed logging
  ENABLE_DETAILED_LOGGING: process.env.NODE_ENV !== 'production',

  // Alert thresholds
  ALERT_THRESHOLDS: {
    // Ban when violations exceed this percentage of requests
    VIOLATION_RATE_THRESHOLD: 5, // 5%

    // Alert when this many IPs are banned
    BANNED_IPS_THRESHOLD: 50,

    // Alert when active keys exceed this
    ACTIVE_KEYS_THRESHOLD: 10000,
  },
};

/**
 * Strategy selection configuration
 */
export const STRATEGY_CONFIG = {
  // Default strategy for all endpoints
  DEFAULT_STRATEGY: 'sliding-window-counter',

  // Strategy for specific categories
  CATEGORY_STRATEGIES: {
    [EndpointCategory.AUTH]: 'sliding-window-log', // Most accurate for auth
    [EndpointCategory.TRADING]: 'token-bucket', // Handle bursts
    [EndpointCategory.WEBHOOK]: 'leaky-bucket', // Smooth traffic
    [EndpointCategory.AI]: 'token-bucket', // Handle bursts
  },
};

/**
 * Redis configuration
 */
export const REDIS_CONFIG = {
  // Key expiration (seconds)
  KEY_EXPIRATION: 3600, // 1 hour

  // Prefix for all rate limiting keys
  KEY_PREFIX: 'ratelimit:',

  // Prefix for violation logs
  VIOLATION_PREFIX: 'violation:',

  // Prefix for ban keys
  BAN_PREFIX: 'ban:',
};

/**
 * Get effective rate limit for a user
 */
export function getEffectiveRateLimit(
  category: EndpointCategory,
  role: UserRole,
): RateLimitConfig {
  const baseLimit = DEFAULT_RATE_LIMITS[category];
  const multiplier = ROLE_MULTIPLIERS[role];

  return {
    limit: Math.ceil(baseLimit.limit * multiplier),
    window: baseLimit.window,
    blockDuration: Math.ceil(BAN_CONFIG.BASE_BAN_DURATION * (1 / multiplier)),
  };
}

/**
 * Calculate ban duration based on violation count
 */
export function calculateBanDuration(violationCount: number): number {
  const excessViolations = Math.max(
    0,
    violationCount - BAN_CONFIG.MAX_VIOLATIONS_BEFORE_BAN,
  );

  const duration =
    BAN_CONFIG.BASE_BAN_DURATION *
    Math.pow(BAN_CONFIG.BAN_BACKOFF_MULTIPLIER, excessViolations);

  return Math.min(duration, BAN_CONFIG.MAX_BAN_DURATION);
}
