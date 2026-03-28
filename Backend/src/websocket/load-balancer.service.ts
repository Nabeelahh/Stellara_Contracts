import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { ConfigService } from '@nestjs/config';
import * as os from 'node:os';

@Injectable()
export class WebsocketLoadBalancerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(WebsocketLoadBalancerService.name);
  private readonly instanceId: string;
  private readonly redisKeyPrefix = 'ws:lb';
  private heartbeatInterval: NodeJS.Timeout;

  constructor(
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {
    this.instanceId = this.configService.get<string>('INSTANCE_ID', os.hostname());
  }

  async onModuleInit() {
    await this.registerInstance();
    this.startHeartbeat();
  }

  async onModuleDestroy() {
    this.stopHeartbeat();
    await this.unregisterInstance();
  }

  private async registerInstance() {
    const key = `${this.redisKeyPrefix}:instances`;
    await this.redisService.getClient().hset(key, this.instanceId, JSON.stringify({
      id: this.instanceId,
      connections: 0,
      lastHeartbeat: Date.now(),
      status: 'active',
    }));
    this.logger.log(`Registered WebSocket instance: ${this.instanceId}`);
  }

  private async unregisterInstance() {
    const key = `${this.redisKeyPrefix}:instances`;
    await this.redisService.getClient().hdel(key, this.instanceId);
    this.logger.log(`Unregistered WebSocket instance: ${this.instanceId}`);
  }

  private startHeartbeat() {
    this.heartbeatInterval = setInterval(async () => {
      await this.sendHeartbeat();
      await this.cleanupStaleInstances();
    }, 10000); // Every 10 seconds
  }

  private stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
  }

  private async sendHeartbeat() {
    const key = `${this.redisKeyPrefix}:instances`;
    const data = await this.redisService.getClient().hget(key, this.instanceId);
    if (data) {
      const parsed = JSON.parse(data as string);
      parsed.lastHeartbeat = Date.now();
      await this.redisService.getClient().hset(key, this.instanceId, JSON.stringify(parsed));
    }
  }

  private async cleanupStaleInstances() {
    const key = `${this.redisKeyPrefix}:instances`;
    const instances = await this.redisService.getClient().hgetall(key);
    const now = Date.now();
    const timeout = 30000; // 30 seconds

    for (const [id, data] of Object.entries(instances)) {
      const parsed = JSON.parse(data as string);
      if (now - parsed.lastHeartbeat > timeout) {
        await this.redisService.getClient().hdel(key, id);
        this.logger.warn(`Stale WebSocket instance removed: ${id}`);
      }
    }
  }

  async reportConnectionChange(delta: number) {
    const key = `${this.redisKeyPrefix}:instances`;
    const data = await this.redisService.getClient().hget(key, this.instanceId);
    if (data) {
      const parsed = JSON.parse(data as string);
      parsed.connections = Math.max(0, parsed.connections + delta);
      await this.redisService.getClient().hset(key, this.instanceId, JSON.stringify(parsed));
    }
  }

  async setUserMapping(userId: string) {
    const key = `${this.redisKeyPrefix}:user-mapping`;
    await this.redisService.getClient().hset(key, userId, this.instanceId);
  }

  async removeUserMapping(userId: string) {
    const key = `${this.redisKeyPrefix}:user-mapping`;
    // We only remove if it's currently mapped to us (to avoid race conditions)
    const currentInstance = await this.redisService.getClient().hget(key, userId);
    if (currentInstance === this.instanceId) {
      await this.redisService.getClient().hdel(key, userId);
    }
  }

  async getInstanceForUser(userId: string): Promise<string | null> {
    const key = `${this.redisKeyPrefix}:user-mapping`;
    return this.redisService.getClient().hget(key, userId);
  }

  async setDrainingStatus() {
    const key = `${this.redisKeyPrefix}:instances`;
    const data = await this.redisService.getClient().hget(key, this.instanceId);
    if (data) {
      const parsed = JSON.parse(data as string);
      parsed.status = 'draining';
      await this.redisService.getClient().hset(key, this.instanceId, JSON.stringify(parsed));
      this.logger.log(`Instance ${this.instanceId} set to draining status`);
    }
  }

  async getHealthStatus() {
    const key = `${this.redisKeyPrefix}:instances`;
    const data = await this.redisService.getClient().hget(key, this.instanceId);
    return data ? JSON.parse(data as string) : null;
  }
}
