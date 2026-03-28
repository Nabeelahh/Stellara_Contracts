import { Injectable, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';

@Injectable()
export class RedisService implements OnApplicationShutdown {
  private readonly client: Redis;
  private readonly bullConnection: RedisOptions;

  constructor(private readonly configService: ConfigService) {
    const host = this.configService.get<string>('REDIS_HOST', 'localhost');
    const port = parseInt(this.configService.get<string>('REDIS_PORT', '6379'), 10);
    const password = this.configService.get<string>('REDIS_PASSWORD');

    this.bullConnection = {
      host,
      port,
      password,
      maxRetriesPerRequest: null,
    };

    this.client = new Redis(this.bullConnection);
  }

  getClient(): Redis {
    return this.client;
  }

  getBullConnection(): RedisOptions {
    return { ...this.bullConnection };
  }

  async ping(): Promise<string> {
    return this.client.ping();
  }

  async onApplicationShutdown(): Promise<void> {
    if (this.client.status === 'end') {
      return;
    }

    await this.client.quit().catch(async () => {
      await this.client.disconnect(false);
    });
  }
}
