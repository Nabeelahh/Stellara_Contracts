/**
 * Rate Limit Decorators
 * Decorators for easy configuration of rate limits on endpoints
 */

import { SetMetadata } from '@nestjs/common';
import {
  EndpointCategory,
  UserRole,
} from './role-based-rate-limit.service';
import { RateLimitStrategyType } from './distributed-rate-limit.service';

/**
 * Rate limit configuration metadata key
 */
export const RATE_LIMIT_KEY = 'rate-limit';

/**
 * Decorator options
 */
export interface RateLimitDecoratorOptions {
  category?: EndpointCategory;
  skipRoles?: UserRole[];
  custom?: string;
  strategy?: RateLimitStrategyType;
}

/**
 * RateLimit decorator
 * Use on controller methods to configure rate limiting
 *
 * @example
 * @RateLimit({ category: EndpointCategory.TRADING })
 * @Post('/trade')
 * async trade() {}
 *
 * @example
 * @RateLimit({
 *   category: EndpointCategory.ADMIN,
 *   skipRoles: [UserRole.ADMIN, UserRole.SYSTEM]
 * })
 * @Post('/admin/action')
 * async adminAction() {}
 */
export function RateLimit(options: RateLimitDecoratorOptions = {}) {
  return SetMetadata(RATE_LIMIT_KEY, {
    category: options.category || EndpointCategory.PUBLIC,
    skipRoles: options.skipRoles || [],
    custom: options.custom,
    strategy: options.strategy || RateLimitStrategyType.SLIDING_WINDOW_COUNTER,
  });
}

/**
 * SkipRateLimit decorator
 * Use on controller methods to skip rate limiting
 *
 * @example
 * @SkipRateLimit()
 * @Get('/health')
 * async health() {}
 */
export function SkipRateLimit() {
  return SetMetadata(RATE_LIMIT_KEY, {
    skipRoles: Object.values(UserRole),
  });
}

/**
 * RateLimitAuth decorator
 * Applies AUTH category rate limits
 */
export function RateLimitAuth() {
  return RateLimit({ category: EndpointCategory.AUTH });
}

/**
 * RateLimitPublic decorator
 * Applies PUBLIC category rate limits
 */
export function RateLimitPublic() {
  return RateLimit({ category: EndpointCategory.PUBLIC });
}

/**
 * RateLimitMarketData decorator
 * Applies MARKET_DATA category rate limits
 */
export function RateLimitMarketData() {
  return RateLimit({ category: EndpointCategory.MARKET_DATA });
}

/**
 * RateLimitTrading decorator
 * Applies TRADING category rate limits
 */
export function RateLimitTrading() {
  return RateLimit({ category: EndpointCategory.TRADING });
}

/**
 * RateLimitWebhook decorator
 * Applies WEBHOOK category rate limits
 */
export function RateLimitWebhook() {
  return RateLimit({ category: EndpointCategory.WEBHOOK });
}

/**
 * RateLimitAI decorator
 * Applies AI category rate limits
 */
export function RateLimitAI() {
  return RateLimit({ category: EndpointCategory.AI });
}

/**
 * RateLimitAdmin decorator
 * Applies ADMIN category rate limits, skips for admins
 */
export function RateLimitAdmin() {
  return RateLimit({
    category: EndpointCategory.ADMIN,
    skipRoles: [UserRole.ADMIN, UserRole.SYSTEM],
  });
}

/**
 * RateLimitTokenBucket decorator
 * Uses token bucket strategy for burst handling
 */
export function RateLimitTokenBucket(category?: EndpointCategory) {
  return RateLimit({
    category: category || EndpointCategory.PUBLIC,
    strategy: RateLimitStrategyType.TOKEN_BUCKET,
  });
}

/**
 * RateLimitLeakyBucket decorator
 * Uses leaky bucket strategy for traffic smoothing
 */
export function RateLimitLeakyBucket(category?: EndpointCategory) {
  return RateLimit({
    category: category || EndpointCategory.PUBLIC,
    strategy: RateLimitStrategyType.LEAKY_BUCKET,
  });
}

/**
 * RateLimitSlidingWindowLog decorator
 * Uses sliding window log strategy (most accurate but memory intensive)
 */
export function RateLimitSlidingWindowLog(category?: EndpointCategory) {
  return RateLimit({
    category: category || EndpointCategory.PUBLIC,
    strategy: RateLimitStrategyType.SLIDING_WINDOW_LOG,
  });
}
