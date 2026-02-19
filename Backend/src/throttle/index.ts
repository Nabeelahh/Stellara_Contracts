/**
 * Throttle Module Exports
 * Central export point for all rate limiting and throttling utilities
 */

// Rate limiting strategies
export {
  RateLimitConfig,
  RateLimitResult,
  RateLimitStrategy,
  RateLimitStrategyType,
  SlidingWindowLogStrategy,
  SlidingWindowCounterStrategy,
  TokenBucketStrategy,
  LeakyBucketStrategy,
} from './rate-limit-strategies';

// Distributed rate limiting service
export {
  DistributedRateLimitService,
  RateLimitIdentifier,
} from './distributed-rate-limit.service';

// Role-based rate limiting
export {
  RoleBasedRateLimitService,
  UserRole,
  EndpointCategory,
} from './role-based-rate-limit.service';

// Guards
export {
  DistributedThrottleGuard,
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
