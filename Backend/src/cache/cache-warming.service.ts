import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { Cron, CronExpression } from '@nestjs/schedule';

export interface CacheAccessEvent {
  key: string;
  timestamp: number;
  userId?: string;
  context?: string;
}

export interface WarmingPrediction {
  key: string;
  score: number;
  tags?: string[];
  fetcher?: () => Promise<any>;
}

@Injectable()
export class CacheWarmingService implements OnModuleInit {
  private readonly logger = new Logger(CacheWarmingService.name);
  
  async onModuleInit() {
    this.logger.log('Mitigating cold start: warming cache on startup...');
    await this.runWarmingCycle();
  }
  private readonly accessLogKey = 'cache:warming:access_log';
  private readonly patternKey = 'cache:warming:patterns';
  private readonly windowSize = 3600; // 1 hour analysis window
  private readonly predictionInterval = 300; // 5 minutes prediction range
  
  // Registry of fetchers for specific keys or key-patterns.
  private readonly fetcherRegistry = new Map<string, (key: string) => Promise<any>>();

  constructor(private readonly redisService: RedisService) {}

  /**
   * Records a cache access event for ML-driven analysis.
   */
  async recordAccess(event: CacheAccessEvent) {
    const redis = this.redisService.getClient();
    const timeBucket = Math.floor(event.timestamp / 60000); // 1-minute buckets
    const member = `${event.key}:${event.userId || 'anon'}:${event.context || 'none'}`;
    
    await redis.zadd(`${this.accessLogKey}:${timeBucket}`, event.timestamp, member);
    // Expire the log after 24 hours to keep Redis clean.
    await redis.expire(`${this.accessLogKey}:${timeBucket}`, 86400);
  }

  /**
   * Registers a data fetcher for a specific key pattern (e.g., "user:profile:*").
   */
  registerFetcher(pattern: string, fetcher: (key: string) => Promise<any>) {
    this.fetcherRegistry.set(pattern, fetcher);
  }

  /**
   * Predicts "hot keys" for the next 5 minutes based on historical access patterns.
   * This implements a weighted statistical prediction (mimicking ML).
   */
  async predictHotKeys(): Promise<WarmingPrediction[]> {
    const redis = this.redisService.getClient();
    const now = Date.now();
    const currentMinute = Math.floor(now / 60000);
    
    // Look at the same 5-minute window from the previous 3 hours (moving average).
    const predictions = new Map<string, number>();
    const hoursToLookBack = [1, 2, 24]; // Same time last hour, two hours, and last day.
    
    for (const hour of hoursToLookBack) {
      const targetMinute = currentMinute - (hour * 60) + 5; // offset to predict ahead.
      const logKey = `${this.accessLogKey}:${targetMinute}`;
      const hits = await redis.zrange(logKey, 0, -1);
      
      for (const hit of hits) {
        const [key] = hit.split(':');
        const weight = hour === 24 ? 0.5 : 1.0; // Recency weighting.
        const currentScore = predictions.get(key) || 0;
        predictions.set(key, currentScore + weight);
      }
    }

    return Array.from(predictions.entries())
      .map(([key, score]) => ({ key, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 100); // Top 100 predictions.
  }

  /**
   * Scheduled job to warm predicted keys every 5 minutes.
   */
  @Cron(CronExpression.EVERY_5_MINUTES)
  async runWarmingCycle() {
    this.logger.log('Starting automated cache warming cycle...');
    const hotKeys = await this.predictHotKeys();
    
    // In a real environment, we'd use a Priority Queue (like BullMQ) with scores.
    for (const prediction of hotKeys) {
      if (prediction.score < 1.0) continue; // Threshold for interest.

      const fetcher = this.findFetcher(prediction.key);
      if (fetcher) {
        this.logger.debug(`Warming hot key: ${prediction.key} (score: ${prediction.score.toFixed(2)})`);
        // The Warming is handled asynchronously to not block.
        this.warmKey(prediction.key, fetcher).catch(err => 
          this.logger.error(`Failed to warm ${prediction.key}: ${err.message}`)
        );
      }
    }
  }

  private findFetcher(key: string) {
    for (const [pattern, fetcher] of this.fetcherRegistry.entries()) {
      if (key.startsWith(pattern.replace('*', ''))) {
        return fetcher;
      }
    }
    return null;
  }

  private async warmKey(key: string, fetcher: (key: string) => Promise<any>) {
    // In production, this would call a shared cache service or a specific provider.
    // We'll expose a hook for AdvancedCacheService later.
    const startTime = Date.now();
    await fetcher(key);
    this.logger.debug(`Warmed ${key} in ${Date.now() - startTime}ms`);
  }
}
