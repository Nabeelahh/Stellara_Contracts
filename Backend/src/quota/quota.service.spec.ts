import { TenantQuotaService } from './quota.service';

class FakePipeline {
  constructor(private readonly redis: FakeRedis) {}
  private commands: Array<() => void> = [];

  del(key: string) {
    this.commands.push(() => this.redis.map.delete(key));
    return this;
  }

  exec() {
    for (const c of this.commands) c();
    return Promise.resolve([]);
  }
}

class FakeRedis {
  map = new Map<string, string>();
  sets = new Map<string, Set<string>>();

  async get(key: string) {
    return this.map.get(key) ?? null;
  }

  async set(key: string, value: string, ...args: any[]) {
    const nx = args.includes('NX');
    if (nx && this.map.has(key)) return null;
    this.map.set(key, value);
    return 'OK';
  }

  async incr(key: string) {
    const current = Number(this.map.get(key) ?? '0');
    const next = current + 1;
    this.map.set(key, String(next));
    return next;
  }

  async expire(_key: string, _seconds: number) {
    return 1;
  }

  async sadd(key: string, value: string) {
    const set = this.sets.get(key) ?? new Set<string>();
    set.add(value);
    this.sets.set(key, set);
    return 1;
  }

  async smembers(key: string) {
    return Array.from(this.sets.get(key) ?? []);
  }

  pipeline() {
    return new FakePipeline(this);
  }
}

describe('TenantQuotaService', () => {
  it('enforces hard-stop policy when limit exceeded', async () => {
    const redis = new FakeRedis();
    const prisma: any = {
      tenantSettings: {
        findUnique: jest.fn().mockResolvedValue({
          apiCallsPerMonthLimit: 1,
          storageGbLimit: 100,
          apiOveragePolicy: 'HARD_STOP',
          maxUsers: 10,
        }),
      },
      user: { count: jest.fn().mockResolvedValue(2), findFirst: jest.fn().mockResolvedValue(null) },
    };
    const service = new TenantQuotaService(
      prisma,
      { getClient: () => redis } as any,
      { notify: jest.fn() } as any,
    );

    await service.consumeApiCallOrThrow('t-1');
    await expect(service.consumeApiCallOrThrow('t-1')).rejects.toBeDefined();
  });

  it('allows overage under BILL_OVERAGE policy', async () => {
    const redis = new FakeRedis();
    const notify = jest.fn();
    const prisma: any = {
      tenantSettings: {
        findUnique: jest.fn().mockResolvedValue({
          apiCallsPerMonthLimit: 1,
          storageGbLimit: 100,
          apiOveragePolicy: 'BILL_OVERAGE',
          maxUsers: 10,
        }),
      },
      user: {
        count: jest.fn().mockResolvedValue(2),
        findFirst: jest.fn().mockResolvedValue({ id: 'admin-1' }),
      },
    };
    const service = new TenantQuotaService(
      prisma,
      { getClient: () => redis } as any,
      { notify } as any,
    );

    await service.consumeApiCallOrThrow('t-2');
    await expect(service.consumeApiCallOrThrow('t-2')).resolves.toBeDefined();
    expect(notify).toHaveBeenCalled();
  });
});
