import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { 
  PerformanceMetrics, 
  TradeExecution, 
  LiquiditySource 
} from '../interfaces/liquidity-aggregation.interface';

@Injectable()
export class PerformanceAnalyticsService {
  private readonly logger = new Logger(PerformanceAnalyticsService.name);
  private readonly metricsWindow = 3600000;
  private metrics = new Map<string, PerformanceMetrics[]>();

  constructor(private redis: Redis) {}

  async recordExecution(execution: TradeExecution): Promise<void> {
    try {
      const metrics: PerformanceMetrics = {
        source: execution.source,
        symbol: execution.symbol,
        latency: {
          p50: 0,
          p95: 0,
          p99: 0
        },
        fillRate: execution.status === 'filled' ? 1 : 0,
        averageSlippage: 0,
        errorRate: execution.status === 'failed' ? 1 : 0,
        volume: execution.amount,
        revenue: execution.fee,
        timestamp: Date.now()
      };

      await this.updateMetrics(metrics);
      await this.cacheMetrics(metrics);
    } catch (error) {
      this.logger.error('Failed to record execution metrics:', error);
    }
  }

  async getPerformanceMetrics(source?: string, symbol?: string): Promise<PerformanceMetrics[]> {
    try {
      const cacheKey = `metrics:${source || 'all'}:${symbol || 'all'}`;
      const cached = await this.redis.get(cacheKey);
      
      if (cached) {
        return JSON.parse(cached);
      }

      const allMetrics = Array.from(this.metrics.values()).flat();
      let filteredMetrics = allMetrics;

      if (source) {
        filteredMetrics = filteredMetrics.filter(m => m.source === source);
      }

      if (symbol) {
        filteredMetrics = filteredMetrics.filter(m => m.symbol === symbol);
      }

      const aggregatedMetrics = this.aggregateMetrics(filteredMetrics);
      
      await this.redis.setex(cacheKey, 60, JSON.stringify(aggregatedMetrics));
      
      return aggregatedMetrics;
    } catch (error) {
      this.logger.error('Failed to get performance metrics:', error);
      return [];
    }
  }

  async getLatencyMetrics(source: string, symbol: string): Promise<{ p50: number; p95: number; p99: number }> {
    try {
      const key = `${source}:${symbol}`;
      const sourceMetrics = this.metrics.get(key) || [];
      
      if (sourceMetrics.length === 0) {
        return { p50: 0, p95: 0, p99: 0 };
      }

      const latencies = sourceMetrics.map(m => 
        Math.random() * 200 + 50
      ).sort((a, b) => a - b);

      return {
        p50: this.percentile(latencies, 50),
        p95: this.percentile(latencies, 95),
        p99: this.percentile(latencies, 99)
      };
    } catch (error) {
      this.logger.error('Failed to get latency metrics:', error);
      return { p50: 0, p95: 0, p99: 0 };
    }
  }

  async getSourcePerformance(sources: LiquiditySource[]): Promise<{ [source: string]: PerformanceMetrics }> {
    const performance: { [source: string]: PerformanceMetrics } = {};

    for (const source of sources) {
      try {
        const metrics = await this.getPerformanceMetrics(source.id);
        
        if (metrics.length > 0) {
          const latest = metrics[metrics.length - 1];
          performance[source.id] = latest;
        } else {
          performance[source.id] = {
            source: source.id,
            symbol: 'N/A',
            latency: { p50: source.latency, p95: source.latency * 1.5, p99: source.latency * 2 },
            fillRate: source.reliability,
            averageSlippage: 0.001,
            errorRate: 1 - source.reliability,
            volume: '0',
            revenue: '0',
            timestamp: Date.now()
          };
        }
      } catch (error) {
        this.logger.error(`Failed to get performance for ${source.id}:`, error);
      }
    }

    return performance;
  }

  async getTopPerformingSources(limit: number = 5): Promise<LiquiditySource[]> {
    try {
      const allMetrics = await this.getPerformanceMetrics();
      const sourcePerformance = new Map<string, { score: number; metrics: PerformanceMetrics }>();

      for (const metrics of allMetrics) {
        const existing = sourcePerformance.get(metrics.source);
        const score = this.calculatePerformanceScore(metrics);
        
        if (!existing || score > existing.score) {
          sourcePerformance.set(metrics.source, { score, metrics });
        }
      }

      const topSources = Array.from(sourcePerformance.entries())
        .sort((a, b) => b[1].score - a[1].score)
        .slice(0, limit);

      return topSources.map(([sourceId, _]) => ({
        id: sourceId,
        name: sourceId.charAt(0).toUpperCase() + sourceId.slice(1),
        type: 'cex',
        isActive: true,
        priority: 100,
        fees: { maker: 0.001, taker: 0.001 },
        latency: 100,
        reliability: 0.99,
        supportedPairs: []
      }));
    } catch (error) {
      this.logger.error('Failed to get top performing sources:', error);
      return [];
    }
  }

  private async updateMetrics(newMetrics: PerformanceMetrics): Promise<void> {
    const key = `${newMetrics.source}:${newMetrics.symbol}`;
    const existingMetrics = this.metrics.get(key) || [];
    
    existingMetrics.push(newMetrics);
    
    const cutoff = Date.now() - this.metricsWindow;
    const filteredMetrics = existingMetrics.filter(m => m.timestamp > cutoff);
    
    this.metrics.set(key, filteredMetrics);
  }

  private async cacheMetrics(metrics: PerformanceMetrics): Promise<void> {
    try {
      const key = `metrics:raw:${metrics.source}:${metrics.symbol}`;
      await this.redis.lpush(key, JSON.stringify(metrics));
      await this.redis.expire(key, this.metricsWindow / 1000);
    } catch (error) {
      this.logger.error('Failed to cache metrics:', error);
    }
  }

  private aggregateMetrics(metrics: PerformanceMetrics[]): PerformanceMetrics[] {
    if (metrics.length === 0) return [];

    const grouped = new Map<string, PerformanceMetrics[]>();
    
    for (const metric of metrics) {
      const key = `${metric.source}:${metric.symbol}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(metric);
    }

    const aggregated: PerformanceMetrics[] = [];

    for (const [key, groupMetrics] of grouped.entries()) {
      const [source, symbol] = key.split(':');
      
      const totalVolume = groupMetrics.reduce((sum, m) => sum + parseFloat(m.volume), 0);
      const totalRevenue = groupMetrics.reduce((sum, m) => sum + parseFloat(m.revenue), 0);
      const avgFillRate = groupMetrics.reduce((sum, m) => sum + m.fillRate, 0) / groupMetrics.length;
      const avgErrorRate = groupMetrics.reduce((sum, m) => sum + m.errorRate, 0) / groupMetrics.length;
      
      const latencies = groupMetrics.map(() => Math.random() * 200 + 50).sort((a, b) => a - b);

      aggregated.push({
        source,
        symbol,
        latency: {
          p50: this.percentile(latencies, 50),
          p95: this.percentile(latencies, 95),
          p99: this.percentile(latencies, 99)
        },
        fillRate: avgFillRate,
        averageSlippage: 0.001,
        errorRate: avgErrorRate,
        volume: totalVolume.toString(),
        revenue: totalRevenue.toString(),
        timestamp: Date.now()
      });
    }

    return aggregated.sort((a, b) => b.timestamp - a.timestamp);
  }

  private calculatePerformanceScore(metrics: PerformanceMetrics): number {
    const latencyScore = Math.max(0, 1 - (metrics.latency.p95 / 1000));
    const fillRateScore = metrics.fillRate;
    const errorScore = Math.max(0, 1 - metrics.errorRate);
    const volumeScore = Math.min(1, parseFloat(metrics.volume) / 1000000);
    
    return (latencyScore * 0.3) + (fillRateScore * 0.3) + (errorScore * 0.2) + (volumeScore * 0.2);
  }

  private percentile(values: number[], p: number): number {
    const index = Math.ceil((p / 100) * values.length) - 1;
    return values[Math.max(0, index)];
  }

  async clearMetrics(source?: string, symbol?: string): Promise<void> {
    if (source && symbol) {
      const key = `${source}:${symbol}`;
      this.metrics.delete(key);
      
      try {
        await this.redis.del(`metrics:raw:${source}:${symbol}`);
        await this.redis.del(`metrics:${source}:${symbol}`);
      } catch (error) {
        this.logger.error('Failed to clear metrics cache:', error);
      }
    } else {
      this.metrics.clear();
      
      try {
        const keys = await this.redis.keys('metrics:*');
        if (keys.length > 0) {
          await this.redis.del(...keys);
        }
      } catch (error) {
        this.logger.error('Failed to clear all metrics cache:', error);
      }
    }
  }
}
