/**
 * Throttle Module Exports
 * Central export point for all rate limiting and throttling utilities
 */

// Rate limiting strategies
export type {
  RateLimitConfig,
  RateLimitResult,
  RateLimitStrategy,
  // RateLimitStrategyType, // Removed - doesn't exist
  SlidingWindowLogStrategy,
  SlidingWindowCounterStrategy,
  TokenBucketStrategy,
  LeakyBucketStrategy,
} from './rate-limit-strategies';

// Distributed rate limiting service
export {
  DistributedRateLimitService,
} from './distributed-rate-limit.service';

export type {
  RateLimitIdentifier,
} from './distributed-rate-limit.service';

// Role-based rate limiting
export {
  RoleBasedRateLimitService,
} from './role-based-rate-limit.service';

export type {
  UserRole,
  EndpointCategory,
} from './role-based-rate-limit.service';

// Guards
export {
  DistributedThrottleGuard,
} from './distributed-throttle.guard';

export type {
  RateLimitMetadata,
} from './distributed-throttle.guard';
export { ThrottleGuard } from './throttle.guard';

// Decorators
export {
  RateLimit,
  SkipRateLimit,
  RateLimitAuth,
  RateLimitPublic,
  RateLimitMarketData,
  RateLimitTrading,
  RateLimitWebhook,
  RateLimitAI,
  RateLimitAdmin,
  RateLimitTokenBucket,
  RateLimitLeakyBucket,
  RateLimitSlidingWindowLog,
  RATE_LIMIT_KEY,
} from './rate-limit.decorators';

// Metrics
export {
  RateLimitMetricsCollector,
} from './rate-limit-metrics.collector';

export type {
  RateLimitMetrics,
} from './rate-limit-metrics.collector';

// Configuration
export {
  DEFAULT_RATE_LIMITS,
  ROLE_MULTIPLIERS,
  BAN_CONFIG,
  MONITORING_CONFIG,
  STRATEGY_CONFIG,
  REDIS_CONFIG,
  getEffectiveRateLimit,
  calculateBanDuration,
} from './rate-limit.config';

// Services
export { ThrottleService } from './throttle.service';

// Module
export { ThrottleModule } from './throttle.module';
