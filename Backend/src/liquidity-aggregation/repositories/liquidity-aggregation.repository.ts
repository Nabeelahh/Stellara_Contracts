import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { 
  AggregatedOrderBook, 
  ArbitrageOpportunity, 
  PerformanceMetrics 
} from '../interfaces/liquidity-aggregation.interface';

@Injectable()
export class LiquidityAggregationRepository {
  private readonly logger = new Logger(LiquidityAggregationRepository.name);

  constructor(private redis: Redis) {}

  async cacheOrderBook(symbol: string, orderBook: AggregatedOrderBook): Promise<void> {
    try {
      const key = `orderbook:${symbol}`;
      await this.redis.setex(key, 30, JSON.stringify(orderBook));
    } catch (error) {
      this.logger.error('Failed to cache order book:', error);
    }
  }

  async getCachedOrderBook(symbol: string): Promise<AggregatedOrderBook | null> {
    try {
      const key = `orderbook:${symbol}`;
      const cached = await this.redis.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      this.logger.error('Failed to get cached order book:', error);
      return null;
    }
  }

  async cacheArbitrageOpportunities(opportunities: ArbitrageOpportunity[]): Promise<void> {
    try {
      const key = 'arbitrage:opportunities';
      await this.redis.setex(key, 60, JSON.stringify(opportunities));
    } catch (error) {
      this.logger.error('Failed to cache arbitrage opportunities:', error);
    }
  }

  async getCachedArbitrageOpportunities(): Promise<ArbitrageOpportunity[]> {
    try {
      const key = 'arbitrage:opportunities';
      const cached = await this.redis.get(key);
      return cached ? JSON.parse(cached) : [];
    } catch (error) {
      this.logger.error('Failed to get cached arbitrage opportunities:', error);
      return [];
    }
  }

  async storePerformanceMetrics(metrics: PerformanceMetrics): Promise<void> {
    try {
      const key = `metrics:${metrics.source}:${metrics.symbol}:${Date.now()}`;
      await this.redis.setex(key, 3600, JSON.stringify(metrics));
    } catch (error) {
      this.logger.error('Failed to store performance metrics:', error);
    }
  }

  async getPerformanceMetrics(source?: string, symbol?: string): Promise<PerformanceMetrics[]> {
    try {
      const pattern = source && symbol 
        ? `metrics:${source}:${symbol}:*`
        : source 
        ? `metrics:${source}:*`
        : symbol
        ? `metrics:*:${symbol}:*`
        : 'metrics:*';
      
      const keys = await this.redis.keys(pattern);
      const metrics: PerformanceMetrics[] = [];

      for (const key of keys) {
        const cached = await this.redis.get(key);
        if (cached) {
          metrics.push(JSON.parse(cached));
        }
      }

      return metrics.sort((a, b) => b.timestamp - a.timestamp);
    } catch (error) {
      this.logger.error('Failed to get performance metrics:', error);
      return [];
    }
  }

  async clearCache(pattern?: string): Promise<void> {
    try {
      const keys = pattern 
        ? await this.redis.keys(pattern)
        : await this.redis.keys('liquidity:*');
      
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } catch (error) {
      this.logger.error('Failed to clear cache:', error);
    }
  }
}
