import { ConflictException, RequestTimeoutException } from '@nestjs/common';
import { AsyncContextService } from '../logging/services/async-context.service';
import { DistributedLockService } from './distributed-lock.service';

class FakeRedisClient {
  private readonly store = new Map<string, { value: string; expiresAt: number | null }>();
  private readonly hashes = new Map<string, Map<string, number>>();

  async set(
    key: string,
    value: string,
    mode?: string,
    ttl?: number,
    condition?: string,
  ): Promise<'OK' | null> {
    this.cleanupExpired();
    if (condition === 'NX' && this.store.has(key)) {
      return null;
    }

    this.store.set(key, {
      value,
      expiresAt: mode === 'PX' && typeof ttl === 'number' ? Date.now() + ttl : null,
    });

    return 'OK';
  }

  async get(key: string): Promise<string | null> {
    this.cleanupExpired();
    return this.store.get(key)?.value ?? null;
  }

  async pttl(key: string): Promise<number> {
    this.cleanupExpired();
    const entry = this.store.get(key);
    if (!entry) {
      return -2;
    }

    if (entry.expiresAt === null) {
      return -1;
    }

    return Math.max(0, entry.expiresAt - Date.now());
  }

  async eval(script: string, _numKeys: number, key: string, token: string, ttlMs?: string) {
    this.cleanupExpired();
    const entry = this.store.get(key);

    if (script.includes("redis.call('del'")) {
      if (entry?.value === token) {
        this.store.delete(key);
        return 1;
      }

      return 0;
    }

    if (script.includes("redis.call('pexpire'")) {
      if (entry?.value === token && ttlMs) {
        entry.expiresAt = Date.now() + Number(ttlMs);
        return 1;
      }

      return 0;
    }

    return 0;
  }

  async hincrbyfloat(key: string, field: string, value: number): Promise<string> {
    const hash = this.hashes.get(key) ?? new Map<string, number>();
    const nextValue = (hash.get(field) ?? 0) + Number(value);
    hash.set(field, nextValue);
    this.hashes.set(key, hash);
    return `${nextValue}`;
  }

  async expire(): Promise<number> {
    return 1;
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const hash = this.hashes.get(key) ?? new Map<string, number>();
    return Array.from(hash.entries()).reduce<Record<string, string>>((acc, [field, value]) => {
      acc[field] = `${value}`;
      return acc;
    }, {});
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) {
        this.store.delete(key);
      }
    }
  }
}

describe('DistributedLockService', () => {
  let redisClient: FakeRedisClient;
  let service: DistributedLockService;

  beforeEach(() => {
    redisClient = new FakeRedisClient();
    service = new DistributedLockService(
      { getClient: () => redisClient } as any,
      new AsyncContextService(),
      {
        setContext: jest.fn(),
        warn: jest.fn(),
      } as any,
    );
  });

  it('acquires and releases a lock automatically', async () => {
    const result = await service.executeWithLock({
      keys: ['user:123'],
      operationName: 'SessionService.rotateRefreshToken',
      operation: async () => 'ok',
    });

    expect(result).toBe('ok');
    expect(await redisClient.get('distributed-lock:user:123')).toBeNull();
    await expect(service.getMetrics('user:123')).resolves.toMatchObject({
      acquired: '1',
      released: '1',
    });
  });

  it('supports reentrant acquisition within the same async execution', async () => {
    const result = await service.executeWithLock({
      keys: ['user:123'],
      operationName: 'outer',
      operation: () =>
        service.executeWithLock({
          keys: ['user:123'],
          operationName: 'inner',
          operation: async () => 'nested',
        }),
    });

    expect(result).toBe('nested');
    await expect(service.getMetrics('user:123')).resolves.toMatchObject({
      acquired: '1',
      released: '1',
      reentrantAcquisitions: '1',
    });
  });

  it('prevents nested locks from being acquired out of order', async () => {
    await expect(
      service.executeWithLock({
        keys: ['user:999'],
        operationName: 'outer',
        operation: () =>
          service.executeWithLock({
            keys: ['trade:123'],
            operationName: 'inner',
            operation: async () => 'never',
          }),
      }),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('times out when another owner keeps the lock', async () => {
    await redisClient.set('distributed-lock:user:123', 'different-owner', 'PX', 1_000, 'NX');

    await expect(
      service.executeWithLock({
        keys: ['user:123'],
        operationName: 'SessionService.terminateSession',
        timeoutMs: 50,
        retryIntervalMs: 10,
        deadlockWarningMs: 20,
        operation: async () => undefined,
      }),
    ).rejects.toBeInstanceOf(RequestTimeoutException);
  });
});
