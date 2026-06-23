import { Injectable, ForbiddenException } from '@nestjs/common';
import { RedisService } from '../../redis/redis.service';

@Injectable()
export class QuotaService {
  private readonly MAX_REQUESTS = 1000;
  // TTL slightly over 31 days so a key always covers its full month
  private readonly TTL_SECONDS = 31 * 24 * 60 * 60;

  constructor(private readonly redis: RedisService) {}

  private requestKey(userId: string): string {
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM
    return `ai:quota:req:${userId}:${month}`;
  }

  private tokenKey(userId: string): string {
    const month = new Date().toISOString().slice(0, 7);
    return `ai:quota:tok:${userId}:${month}`;
  }

  async assertQuota(userId: string): Promise<void> {
    const key = this.requestKey(userId);
    const count = await this.redis.client.get(key);

    if (count !== null && parseInt(count, 10) >= this.MAX_REQUESTS) {
      throw new ForbiddenException({
        error: 'QuotaExceeded',
        message: 'Monthly AI usage quota exceeded',
      });
    }
  }

  async recordUsage(userId: string, tokens: number): Promise<void> {
    const rKey = this.requestKey(userId);
    const tKey = this.tokenKey(userId);

    // Atomic increment; set TTL only on first write
    const reqCount = await this.redis.client.incr(rKey);
    if (reqCount === 1) {
      await this.redis.client.expire(rKey, this.TTL_SECONDS);
    }

    const tokCount = await this.redis.client.incrBy(tKey, tokens);
    if (tokCount === tokens) {
      await this.redis.client.expire(tKey, this.TTL_SECONDS);
    }
  }
}
