import { IoAdapter } from '@nestjs/platform-socket.io';
import { ServerOptions } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { RedisService } from '../../redis/redis.service';
import { INestApplicationContext } from '@nestjs/common';

export class RedisIoAdapter extends IoAdapter {
  private adapterConstructor: ReturnType<typeof createAdapter>;

  constructor(private app: INestApplicationContext) {
    super(app);
  }

  async connectToRedis(): Promise<void> {
    const redisService = this.app.get(RedisService);
    const pubClient = redisService.getClient();
    const subClient = pubClient.duplicate();

    await Promise.all([pubClient.connect(), subClient.connect()]).catch(() => {
      // ioredis client might already be connected or handle connection automatically
      // However, duplicate() for ioredis might need explicit connect if not already handled
    });

    this.adapterConstructor = createAdapter(pubClient, subClient);
  }

  createIOServer(port: number, options?: ServerOptions): any {
    const server = super.createIOServer(port, options);
    server.adapter(this.adapterConstructor);
    return server;
  }
}
