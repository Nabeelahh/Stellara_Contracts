import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../../redis/redis.service';
import { HealthIndicatorResult, RedisHealthDetails } from '../health.types';

@Injectable()
export class RedisHealthIndicator {
  private readonly logger = new Logger(RedisHealthIndicator.name);

  constructor(private readonly redisService: RedisService) {}

  async isHealthy(): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Check if Redis service is available
      if (!this.redisService.isRedisAvailable()) {
        return {
          name: 'redis',
          status: 'down',
          message: 'Redis service is not available',
          timestamp: new Date().toISOString(),
        };
      }

      // Test Redis connection with a simple ping
      const client = this.redisService.client;
      await client.ping();
      
      const latency = Date.now() - startTime;
      
      // Get Redis info
      const info = await this.getRedisInfo();
      
      const details: RedisHealthDetails = {
        connection: true,
        latency,
        memory: {
          used: info.usedMemory,
          max: info.maxMemory,
          percentage: info.maxMemory > 0 ? (info.usedMemory / info.maxMemory) * 100 : 0,
        },
        keys: info.keyCount,
      };

      let status = 'up';
      let message = 'Redis is healthy';
      
      // Check for potential issues
      if (latency > 500) {
        status = 'degraded';
        message = `Redis latency is high: ${latency}ms`;
      }
      
      if (details.memory.percentage > 90) {
        status = 'degraded';
        message = `Redis memory usage is high: ${details.memory.percentage.toFixed(2)}%`;
      }

      return {
        name: 'redis',
        status,
        message,
        details,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('Redis health check failed', error);
      
      return {
        name: 'redis',
        status: 'down',
        message: `Redis connection failed: ${error.message}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  private async getRedisInfo(): Promise<{
    usedMemory: number;
    maxMemory: number;
    keyCount: number;
  }> {
    try {
      const client = this.redisService.client;
      
      // Get memory info
      const memoryInfo = await client.info('memory');
      const usedMemory = this.parseInfoValue(memoryInfo, 'used_memory') || 0;
      const maxMemory = this.parseInfoValue(memoryInfo, 'maxmemory') || 0;
      
      // Get key count (approximate)
      const keyCount = await client.dbSize();
      
      return {
        usedMemory: parseInt(usedMemory, 10) || 0,
        maxMemory: parseInt(maxMemory, 10) || 0,
        keyCount,
      };
    } catch (error) {
      this.logger.warn('Could not get Redis info', error);
      return {
        usedMemory: 0,
        maxMemory: 0,
        keyCount: 0,
      };
    }
  }

  private parseInfoValue(info: string, key: string): string | null {
    const lines = info.split('\n');
    for (const line of lines) {
      if (line.startsWith(`${key}:`)) {
        return line.split(':')[1]?.trim() || null;
      }
    }
    return null;
  }
}