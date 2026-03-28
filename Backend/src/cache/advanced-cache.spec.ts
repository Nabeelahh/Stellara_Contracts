import { AdvancedCacheService } from './advanced-cache.service';

class FakePipeline {
  private readonly cmds: Array<() => void> = [];
  incr(key: string) {
    this.cmds.push(() => {
      const v = Number((this as any)._redis.map.get(key) ?? '0') + 1;
      (this as any)._redis.map.set(key, String(v));
    });
    return this;
  }
  del(_key: string) {
    return this;
  }
  exec() {
    for (const cmd of this.cmds) cmd();
    return Promise.resolve([]);
  }
}

class FakeRedis {
  map = new Map<string, string>();
  pipeline() {
    const p: any = new FakePipeline();
    p._redis = this;
    return p;
  }

  async get(key: string) {
    return this.map.get(key) ?? null;
  }

  async set(key: string, value: string, ..._args: any[]) {
    this.map.set(key, value);
    return 'OK';
  }

  async incr(key: string) {
    const v = Number(this.map.get(key) ?? '0') + 1;
    this.map.set(key, String(v));
    return v;
  }
}

describe('AdvancedCacheService', () => {
  it('uses cache-aside and supports tag-based invalidation', async () => {
    const fakeRedis = new FakeRedis();
    const redisService = { getClient: () => fakeRedis } as any;

    const cache = new AdvancedCacheService(redisService);

    let fetchCount = 0;
    const fetcher = async () => {
      fetchCount += 1;
      return { ok: true, n: fetchCount };
    };

    const v1 = await cache.getOrSet('key1', fetcher, { ttlSeconds: 60 }, ['tag1']);
    const v2 = await cache.getOrSet('key1', fetcher, { ttlSeconds: 60 }, ['tag1']);

    expect(fetchCount).toBe(1);
    expect(v1).toEqual(v2);

    await cache.invalidateTags(['tag1']);

    const v3 = await cache.getOrSet('key1', fetcher, { ttlSeconds: 60 }, ['tag1']);
    expect(fetchCount).toBe(2);
    expect(v3.n).toBe(2);
  });
});
