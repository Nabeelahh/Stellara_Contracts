/**
 * Distributed Rate Limiting Service
 * Manages rate limits across multiple backend instances using Redis
 */

import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import {
  RateLimitConfig,
  RateLimitResult,
  RateLimitStrategy,
  SlidingWindowCounterStrategy,
  SlidingWindowLogStrategy,
  TokenBucketStrategy,
  LeakyBucketStrategy,
} from './rate-limit-strategies';

/**
 * Strategy type enumeration
 */
export enum RateLimitStrategyType {
  SLIDING_WINDOW_LOG = 'sliding-window-log',
  SLIDING_WINDOW_COUNTER = 'sliding-window-counter',
  TOKEN_BUCKET = 'token-bucket',
  LEAKY_BUCKET = 'leaky-bucket',
}

/**
 * Rate limit identifier components
 */
export interface RateLimitIdentifier {
  ip: string;
  userId?: string;
  path: string;
  custom?: string;
}

/**
 * Distributed rate limiting service
 */
@Injectable()
export class DistributedRateLimitService {
  private readonly logger = new Logger('DistributedRateLimiter');
  private strategies: Map<RateLimitStrategyType, RateLimitStrategy> = new Map();

  constructor(private redisService: RedisService) {
    this.initializeStrategies();
  }

  /**
   * Initialize rate limiting strategies
   */
  private initializeStrategies(): void {
    const redis = this.redisService.client;

    this.strategies.set(
      RateLimitStrategyType.SLIDING_WINDOW_LOG,
      new SlidingWindowLogStrategy(redis),
    );
    this.strategies.set(
      RateLimitStrategyType.SLIDING_WINDOW_COUNTER,
      new SlidingWindowCounterStrategy(redis),
    );
    this.strategies.set(
      RateLimitStrategyType.TOKEN_BUCKET,
      new TokenBucketStrategy(redis),
    );
    this.strategies.set(
      RateLimitStrategyType.LEAKY_BUCKET,
      new LeakyBucketStrategy(redis),
    );

    this.logger.log('Rate limiting strategies initialized');
  }

  /**
   * Check rate limit with specified strategy
   */
  async checkRateLimit(
    identifier: RateLimitIdentifier,
    config: RateLimitConfig,
    strategyType: RateLimitStrategyType = RateLimitStrategyType.SLIDING_WINDOW_COUNTER,
  ): Promise<RateLimitResult> {
    const key = this.buildKey(identifier);
    const strategy = this.strategies.get(strategyType);

    if (!strategy) {
      throw new Error(`Unknown rate limit strategy: ${strategyType}`);
    }

    const result = await strategy.check(key, config);

    // Log violations
    if (!result.allowed) {
      await this.recordViolation(identifier, config);
    }

    return result;
  }

  /**
   * Record rate limit violation for monitoring
   */
  private async recordViolation(
    identifier: RateLimitIdentifier,
    config: RateLimitConfig,
  ): Promise<void> {
    const violationKey = `violations:${this.buildKey(identifier)}`;
    const violations = await this.redisService.client.incr(violationKey);

    if (violations === 1) {
      await this.redisService.client.expire(
        violationKey,
        config.window * 2,
      );
    }

    // Log violation
    const timestamp = new Date().toISOString();
    const logKey = `violation:log:${identifier.ip}`;
    await this.redisService.client.rPush(
      logKey,
      JSON.stringify({
        timestamp,
        userId: identifier.userId,
        path: identifier.path,
        violations,
      }),
    );

    // Keep log size limited (last 100 entries)
    await this.redisService.client.lTrim(logKey, -100, -1);

    this.logger.warn(
      `Rate limit violation: IP=${identifier.ip}, UserId=${identifier.userId}, Path=${identifier.path}`,
    );
  }

  /**
   * Reset rate limit for identifier
   */
  async resetRateLimit(
    identifier: RateLimitIdentifier,
    strategyType: RateLimitStrategyType = RateLimitStrategyType.SLIDING_WINDOW_COUNTER,
  ): Promise<void> {
    const key = this.buildKey(identifier);
    const strategy = this.strategies.get(strategyType);

    if (!strategy) {
      throw new Error(`Unknown rate limit strategy: ${strategyType}`);
    }

    await strategy.reset(key);
    this.logger.log(`Rate limit reset for: ${key}`);
  }

  /**
   * Reset all rate limits matching pattern
   */
  async resetAllRateLimits(
    pattern: string,
    strategyType: RateLimitStrategyType = RateLimitStrategyType.SLIDING_WINDOW_COUNTER,
  ): Promise<void> {
    const strategy = this.strategies.get(strategyType);

    if (!strategy) {
      throw new Error(`Unknown rate limit strategy: ${strategyType}`);
    }

    await strategy.reset_all(pattern);
    this.logger.log(`Rate limit reset for pattern: ${pattern}`);
  }

  /**
   * Get violation history for identifier
   */
  async getViolationHistory(
    identifier: RateLimitIdentifier,
  ): Promise<Array<{ timestamp: string; userId?: string; path: string; violations: number }>> {
    const logKey = `violation:log:${identifier.ip}`;
    const logs = await this.redisService.client.lRange(logKey, 0, -1);

    return logs.map((log) => JSON.parse(log));
  }

  /**
   * Check if identifier is temporarily banned
   */
  async isBanned(identifier: RateLimitIdentifier): Promise<boolean> {
    const banKey = `ban:${this.buildKey(identifier)}`;
    const banned = await this.redisService.client.exists(banKey);
    return banned === 1;
  }

  /**
   * Ban identifier for specified duration
   */
  async banIdentifier(
    identifier: RateLimitIdentifier,
    durationSeconds: number,
  ): Promise<void> {
    const banKey = `ban:${this.buildKey(identifier)}`;
    await this.redisService.client.setEx(
      banKey,
      durationSeconds,
      JSON.stringify({
        bannedAt: new Date().toISOString(),
        banDuration: durationSeconds,
      }),
    );

    this.logger.warn(
      `Banned identifier: IP=${identifier.ip}, UserId=${identifier.userId}, Duration=${durationSeconds}s`,
    );
  }

  /**
   * Unban identifier
   */
  async unbanIdentifier(identifier: RateLimitIdentifier): Promise<void> {
    const banKey = `ban:${this.buildKey(identifier)}`;
    await this.redisService.client.del(banKey);

    this.logger.log(
      `Unbanned identifier: IP=${identifier.ip}, UserId=${identifier.userId}`,
    );
  }

  /**
   * Get rate limit metrics for identifier
   */
  async getMetrics(identifier: RateLimitIdentifier): Promise<{
    violations: number;
    isBanned: boolean;
    violationHistory: Array<any>;
  }> {
    const key = this.buildKey(identifier);
    const violationKey = `violations:${key}`;
    const violations = await this.redisService.client.get(violationKey);
    const isBanned = await this.isBanned(identifier);
    const violationHistory = await this.getViolationHistory(identifier);

    return {
      violations: parseInt(violations || '0', 10),
      isBanned,
      violationHistory,
    };
  }

  /**
   * Build cache key from identifier
   */
  private buildKey(identifier: RateLimitIdentifier): string {
    const parts = [identifier.ip, identifier.userId || 'anonymous', identifier.path];
    if (identifier.custom) {
      parts.push(identifier.custom);
    }
    return parts.join(':');
  }

  /**
   * Get all active rate limit keys
   */
  async getActiveKeys(): Promise<string[]> {
    const keys = await this.redisService.client.keys('swc:*');
    return keys;
  }

  /**
   * Get system-wide rate limit statistics
   */
  async getSystemStats(): Promise<{
    totalActiveKeys: number;
    totalViolations: number;
    bannedIdentifiers: number;
  }> {
    const activeKeys = await this.getActiveKeys();
    const violationKeys = await this.redisService.client.keys('violations:*');
    const bannedKeys = await this.redisService.client.keys('ban:*');

    return {
      totalActiveKeys: activeKeys.length,
      totalViolations: violationKeys.length,
      bannedIdentifiers: bannedKeys.length,
    };
  }
}
