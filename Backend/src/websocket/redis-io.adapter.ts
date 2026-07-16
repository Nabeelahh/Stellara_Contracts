import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { Logger } from '@nestjs/common';

/** Inline URL masker — used before DI is available. */
function maskRedisUrl(url: string): string {
  return url.replace(/(rediss?:\/\/[^:@\s]*:)[^@\s]+(@)/gi, '$1***$2');
}

export class RedisIoAdapter extends IoAdapter {
  private adapterConstructor: ReturnType<typeof createAdapter> | undefined;
  private readonly logger = new Logger(RedisIoAdapter.name);

  async connectToRedis(): Promise<void> {
    const redisUrl = process.env.REDIS_URL || `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`;

    // Log only the masked URL so embedded passwords never appear in logs
    this.logger.log(`Initializing Redis clients at ${maskRedisUrl(redisUrl)}`);

    const socketOptions = {
      reconnectStrategy: (retries: number) => {
        const maxRetries = 5;
        if (retries >= maxRetries) {
          this.logger.error(`Redis connection failed after ${maxRetries} attempts. Falling back to in-memory mode.`);
          return new Error('Redis connection max retries reached');
        }
        const delay = Math.min(1000 * Math.pow(2, retries), 30000);
        this.logger.log(`Retrying Redis connection in ${delay}ms...`);
        return delay;
      },
    };

    const pubClient = createClient({ url: redisUrl, socket: socketOptions });
    const subClient = pubClient.duplicate();

    // Mask error messages before logging — err.message can contain connection URLs
    pubClient.on('error', (err) => this.logger.error(`Redis Pub Client Error: ${maskRedisUrl(err.message)}`));
    subClient.on('error', (err) => this.logger.error(`Redis Sub Client Error: ${maskRedisUrl(err.message)}`));

    try {
      await Promise.all([pubClient.connect(), subClient.connect()]);
      this.adapterConstructor = createAdapter(pubClient, subClient);
      this.logger.log('Redis adapter initialized successfully');
    } catch (error) {
      this.logger.warn(`Failed to connect to Redis during bootstrap. Initializing in-memory fallback.`);
      this.adapterConstructor = undefined;
    }
  }

  createIOServer(port: number, options?: any) {
    const server = super.createIOServer(port, options);

    if (this.adapterConstructor) {
      server.adapter(this.adapterConstructor);
      this.logger.log('Redis adapter applied to WebSocket server');
    } else {
      this.logger.warn('Running WebSocket without Redis adapter (fallback to in-memory mode)');
    }

    return server;
  }
}
