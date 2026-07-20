import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

export interface HealthCheckResult {
  status: 'ok' | 'error';
  message?: string;
  responseTimeMs?: number;
}

@Injectable()
export class RedisHealthIndicator {
  private readonly logger = new Logger(RedisHealthIndicator.name);

  constructor(private readonly redisService: RedisService) {}

  async isHealthy(): Promise<HealthCheckResult> {
    const start = Date.now();
    try {
      await this.redisService.client.ping();
      return {
        status: 'ok',
        responseTimeMs: Date.now() - start,
      };
    } catch (err: any) {
      this.logger.warn(`Redis health check failed: ${err.message}`);
      return {
        status: 'error',
        message: err.message,
        responseTimeMs: Date.now() - start,
      };
    }
  }
}
