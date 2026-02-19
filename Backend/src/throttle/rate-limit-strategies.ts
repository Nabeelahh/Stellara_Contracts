/**
 * Distributed Rate Limiting Strategy
 * Implements multiple rate limiting algorithms for different scenarios
 */

import { RedisClientType } from 'redis';

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  limit: number;
  window: number; // seconds
  blockDuration?: number; // seconds (optional, for banning)
}

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  allowed: boolean;
  current: number;
  limit: number;
  remaining: number;
  resetTime: number; // Unix timestamp
  resetIn: number; // seconds
  retryAfter?: number; // seconds (when blocked)
}

/**
 * Rate limiting strategy interface
 */
export interface RateLimitStrategy {
  check(key: string, config: RateLimitConfig): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
  reset_all(pattern: string): Promise<void>;
}

/**
 * Sliding Window Log Strategy
 * Maintains a log of all requests in a time window
 * Most accurate but uses more memory
 */
export class SlidingWindowLogStrategy implements RateLimitStrategy {
  constructor(private redis: RedisClientType) {}

  async check(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - config.window * 1000;
    const logKey = `swl:${key}`;

    // Remove old entries
    await this.redis.zRemRangeByScore(logKey, 0, windowStart);

    // Count requests in window
    const current = await this.redis.zCard(logKey);

    const allowed = current < config.limit;

    // Add current request if allowed
    if (allowed) {
      await this.redis.zAdd(logKey, { score: now, member: `${now}:${Math.random()}` });
    }

    // Set expiration
    await this.redis.expire(logKey, config.window + 10);

    const resetTime = windowStart + config.window * 1000;
    const resetIn = Math.max(0, Math.ceil((resetTime - now) / 1000));

    return {
      allowed,
      current,
      limit: config.limit,
      remaining: Math.max(0, config.limit - current),
      resetTime: Math.floor(resetTime / 1000),
      resetIn,
    };
  }

  async reset(key: string): Promise<void> {
    const logKey = `swl:${key}`;
    await this.redis.del(logKey);
  }

  async reset_all(pattern: string): Promise<void> {
    const keys = await this.redis.keys(`swl:${pattern}`);
    if (keys.length > 0) {
      await this.redis.del(keys);
    }
  }
}

/**
 * Sliding Window Counter Strategy
 * Divides time into fixed windows and counts requests
 * Faster and uses less memory, but less accurate
 */
export class SlidingWindowCounterStrategy implements RateLimitStrategy {
  constructor(private redis: RedisClientType) {}

  async check(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const currentWindow = Math.floor(now / (config.window * 1000));
    const previousWindow = currentWindow - 1;

    const currentKey = `swc:${key}:${currentWindow}`;
    const previousKey = `swc:${key}:${previousWindow}`;

    // Get counts from current and previous windows
    const [currentCount, previousCount] = await Promise.all([
      this.redis.get(currentKey),
      this.redis.get(previousKey),
    ]);

    const current = parseInt(currentCount || '0', 10);
    const previous = parseInt(previousCount || '0', 10);

    // Calculate weighted count
    const timePassedPercent =
      ((now % (config.window * 1000)) / (config.window * 1000)) * 100;
    const weightedPrevious = Math.ceil(
      previous * ((100 - timePassedPercent) / 100),
    );
    const estimatedCount = current + weightedPrevious;

    const allowed = estimatedCount < config.limit;

    // Increment current window
    if (allowed) {
      await this.redis.incr(currentKey);
    }

    // Set expiration for both windows
    await this.redis.expire(currentKey, config.window * 2);
    await this.redis.expire(previousKey, config.window * 2);

    const resetTime = (currentWindow + 1) * config.window * 1000;
    const resetIn = Math.ceil((resetTime - now) / 1000);

    return {
      allowed,
      current: estimatedCount,
      limit: config.limit,
      remaining: Math.max(0, config.limit - estimatedCount),
      resetTime: Math.floor(resetTime / 1000),
      resetIn,
    };
  }

  async reset(key: string): Promise<void> {
    const pattern = `swc:${key}:*`;
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(keys);
    }
  }

  async reset_all(pattern: string): Promise<void> {
    const keys = await this.redis.keys(`swc:${pattern}:*`);
    if (keys.length > 0) {
      await this.redis.del(keys);
    }
  }
}

/**
 * Token Bucket Strategy
 * Tokens are added at a fixed rate, requests consume tokens
 * Good for handling bursts
 */
export class TokenBucketStrategy implements RateLimitStrategy {
  constructor(private redis: RedisClientType) {}

  async check(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const bucketKey = `tb:${key}:bucket`;
    const lastRefillKey = `tb:${key}:refill`;

    // Get current state
    let tokens = parseInt(await this.redis.get(bucketKey) || '0', 10);
    let lastRefill = parseInt(await this.redis.get(lastRefillKey) || '0', 10);

    if (lastRefill === 0) {
      lastRefill = now;
      tokens = config.limit;
    }

    // Calculate tokens to add
    const timePassed = (now - lastRefill) / 1000;
    const tokensToAdd = timePassed * (config.limit / config.window);
    tokens = Math.min(config.limit, tokens + tokensToAdd);

    // Check if request can be fulfilled
    const allowed = tokens >= 1;

    if (allowed) {
      tokens -= 1;
    }

    // Store updated state
    await this.redis.setEx(bucketKey, config.window * 2, Math.floor(tokens).toString());
    await this.redis.setEx(lastRefillKey, config.window * 2, now.toString());

    const resetTime = now + config.window * 1000;
    const resetIn = config.window;

    return {
      allowed,
      current: config.limit - Math.ceil(tokens),
      limit: config.limit,
      remaining: Math.max(0, Math.floor(tokens)),
      resetTime: Math.floor(resetTime / 1000),
      resetIn,
    };
  }

  async reset(key: string): Promise<void> {
    await this.redis.del([`tb:${key}:bucket`, `tb:${key}:refill`]);
  }

  async reset_all(pattern: string): Promise<void> {
    const bucketKeys = await this.redis.keys(`tb:${pattern}:bucket`);
    const refillKeys = await this.redis.keys(`tb:${pattern}:refill`);
    const allKeys = [...bucketKeys, ...refillKeys];
    if (allKeys.length > 0) {
      await this.redis.del(allKeys);
    }
  }
}

/**
 * Leaky Bucket Strategy
 * Requests go into a bucket and are processed at a fixed rate
 * Good for traffic smoothing
 */
export class LeakyBucketStrategy implements RateLimitStrategy {
  constructor(private redis: RedisClientType) {}

  async check(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const queueKey = `lb:${key}:queue`;
    const lastLeakKey = `lb:${key}:leak`;
    const leakRate = config.limit / config.window; // requests per second

    // Get current queue size
    let queueSize = await this.redis.lLen(queueKey);
    let lastLeak = parseInt(await this.redis.get(lastLeakKey) || '0', 10);

    if (lastLeak === 0) {
      lastLeak = now;
    }

    // Calculate how many requests have leaked
    const timePassed = (now - lastLeak) / 1000;
    const leaked = Math.floor(timePassed * leakRate);

    if (leaked > 0) {
      // Remove leaked requests
      for (let i = 0; i < Math.min(leaked, queueSize); i++) {
        await this.redis.lPop(queueKey);
      }
      queueSize = Math.max(0, queueSize - leaked);
      await this.redis.set(lastLeakKey, now.toString());
    }

    const allowed = queueSize < config.limit;

    if (allowed) {
      await this.redis.rPush(queueKey, `${now}`);
      queueSize += 1;
    }

    // Set expiration
    await this.redis.expire(queueKey, config.window * 2);
    await this.redis.expire(lastLeakKey, config.window * 2);

    const resetTime = now + config.window * 1000;
    const resetIn = config.window;

    return {
      allowed,
      current: queueSize,
      limit: config.limit,
      remaining: Math.max(0, config.limit - queueSize),
      resetTime: Math.floor(resetTime / 1000),
      resetIn,
    };
  }

  async reset(key: string): Promise<void> {
    await this.redis.del([`lb:${key}:queue`, `lb:${key}:leak`]);
  }

  async reset_all(pattern: string): Promise<void> {
    const queueKeys = await this.redis.keys(`lb:${pattern}:queue`);
    const leakKeys = await this.redis.keys(`lb:${pattern}:leak`);
    const allKeys = [...queueKeys, ...leakKeys];
    if (allKeys.length > 0) {
      await this.redis.del(allKeys);
    }
  }
}
