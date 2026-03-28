import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { CacheWarmingService } from './cache-warming.service';

type CacheStats = {
  l1Hits: number;
  l2Hits: number;
  misses: number;
  evictions: number;
  sets: number;
  inflightCoalesced: number;
};

type CacheOptions<T = unknown> = {
  ttlSeconds?: number;
  tags?: string[];
};

type L1Entry<T> = {
  value: T;
  expiresAt: number;
  lastAccess: number;
};

function nowMs(): number {
  return Date.now();
}

function computeExpiresAt(ttlSeconds: number | undefined): number {
  if (!ttlSeconds || ttlSeconds <= 0) return Infinity;
  return nowMs() + ttlSeconds * 1000;
}

@Injectable()
export class AdvancedCacheService {
  private readonly logger = new Logger(AdvancedCacheService.name);

  private readonly l1MaxEntries = Number(process.env.CACHE_L1_MAX_ENTRIES ?? 5000);
  private readonly defaultTtlSeconds = Number(process.env.CACHE_TTL_SECONDS ?? 60);
  private readonly schemaCacheVersion = String(process.env.CACHE_SCHEMA_VERSION ?? '1');

  // L1: Map implements insertion order; we treat it as an LRU by deleting+re-inserting on access.
  private readonly l1 = new Map<string, L1Entry<unknown>>();
  private readonly stats: CacheStats = {
    l1Hits: 0,
    l2Hits: 0,
    misses: 0,
    evictions: 0,
    sets: 0,
    inflightCoalesced: 0,
  };

  // Tag version cache to reduce round-trips.
  private readonly tagVersionCache = new Map<string, { version: number; expiresAt: number }>();
  private readonly tagVersionCacheTtlMs = 30_000;

  // In-flight single-flight to protect hot keys from stampedes.
  private readonly inflight = new Map<string, Promise<unknown>>();

  // Hot key detection (simple access counting in memory).
  private readonly hotKeyAccess = new Map<string, { count: number; firstSeenAt: number }>();
  private readonly hotKeyWindowMs = Number(process.env.CACHE_HOTKEY_WINDOW_MS ?? 60_000);
  private readonly hotKeyThreshold = Number(process.env.CACHE_HOTKEY_THRESHOLD ?? 100);
  private readonly hotKeyTtlBoostSeconds = Number(
    process.env.CACHE_HOTKEY_TTL_BOOST_SECONDS ?? 120,
  );

  constructor(
    private readonly redisService: RedisService,
    private readonly warmingService: CacheWarmingService,
  ) {}

  private l1TtlSeconds(options?: CacheOptions): number {
    return options?.ttlSeconds ?? this.defaultTtlSeconds;
  }

  private tagVersionKey(tag: string): string {
    return `cache:tag:${tag}:version`;
  }

  private cacheKey(baseKey: string, tags?: string[]): string {
    const tagSuffix = (tags?.length ? tags.sort().join('|') : 'no-tags').replace(
      /[^a-zA-Z0-9:|_-]/g,
      '_',
    );
    return `${this.schemaCacheVersion}:${tagSuffix}:${baseKey}`;
  }

  private async getTagVersions(tags: string[] = []): Promise<string> {
    if (!tags.length) return 'none';

    const redis = this.redisService.getClient();
    const versions: string[] = [];

    for (const tag of tags) {
      const cached = this.tagVersionCache.get(tag);
      if (cached && cached.expiresAt > nowMs()) {
        versions.push(`${tag}=${cached.version}`);
        continue;
      }

      const versionRaw = await redis.get(this.tagVersionKey(tag));
      const version = versionRaw ? Number(versionRaw) : 1;

      // Ensure version exists (lazy init).
      if (!versionRaw) {
        await redis.set(this.tagVersionKey(tag), String(version), 'EX', 86400);
      }

      this.tagVersionCache.set(tag, { version, expiresAt: nowMs() + this.tagVersionCacheTtlMs });
      versions.push(`${tag}=${version}`);
    }

    return versions.join(',');
  }

  private async effectiveKey(baseKey: string, tags?: string[]): Promise<string> {
    const versionSuffix = await this.getTagVersions(tags ?? []);
    // Cache versioning for schema changes is encoded in `schemaCacheVersion`.
    return `${this.schemaCacheVersion}:v:${versionSuffix}:k:${baseKey}`;
  }

  private markHotKeyAccess(key: string, ttlSeconds: number | undefined): number {
    const t = nowMs();
    const existing = this.hotKeyAccess.get(key);
    if (!existing || t - existing.firstSeenAt > this.hotKeyWindowMs) {
      this.hotKeyAccess.set(key, { count: 1, firstSeenAt: t });
      return ttlSeconds ?? this.defaultTtlSeconds;
    }

    existing.count += 1;
    this.hotKeyAccess.set(key, existing);

    if (existing.count >= this.hotKeyThreshold) {
      return (ttlSeconds ?? this.defaultTtlSeconds) + this.hotKeyTtlBoostSeconds;
    }

    return ttlSeconds ?? this.defaultTtlSeconds;
  }

  private getL1(key: string): unknown | undefined {
    const entry = this.l1.get(key);
    if (!entry) return undefined;

    if (entry.expiresAt <= nowMs()) {
      this.l1.delete(key);
      return undefined;
    }

    // LRU update: move to end.
    this.l1.delete(key);
    this.l1.set(key, entry);
    entry.lastAccess = nowMs();
    return entry.value;
  }

  private setL1(key: string, value: unknown, ttlSeconds: number): void {
    const expiresAt = computeExpiresAt(ttlSeconds);

    // Evict LRU if needed.
    while (this.l1.size >= this.l1MaxEntries) {
      const first = this.l1.keys().next().value as string | undefined;
      if (!first) break;
      this.l1.delete(first);
      this.stats.evictions += 1;
    }

    this.l1.set(key, { value, expiresAt, lastAccess: nowMs() });
  }

  async invalidateTags(tags: string[]): Promise<void> {
    if (!tags?.length) return;
    const redis = this.redisService.getClient();

    const pipeline = redis.pipeline();
    for (const tag of tags) {
      pipeline.incr(this.tagVersionKey(tag));
    }
    await pipeline.exec();

    // Update in-memory cache for tag versions.
    for (const tag of tags) {
      this.tagVersionCache.delete(tag);
    }
  }

  async getOrSet<T>(
    baseKey: string,
    fetcher: () => Promise<T>,
    options: CacheOptions<T> = {},
    tags: string[] = [],
  ): Promise<T> {
    const ttlSeconds = this.markHotKeyAccess(baseKey, options.ttlSeconds);
    const effective = await this.effectiveKey(baseKey, tags);

    const l1Value = this.getL1(effective);
    if (l1Value !== undefined) {
      this.stats.l1Hits += 1;
      this.warmingService.recordAccess({ key: baseKey, timestamp: nowMs() });
      return l1Value as T;
    }

    // In-flight single-flight coalescing.
    const inflight = this.inflight.get(effective);
    if (inflight) {
      this.stats.inflightCoalesced += 1;
      this.warmingService.recordAccess({ key: baseKey, timestamp: nowMs() });
      return (await inflight) as T;
    }

    const redis = this.redisService.getClient();
    const l2Raw = await redis.get(`cache:l2:${effective}`);
    if (l2Raw !== null && l2Raw !== undefined) {
      this.stats.l2Hits += 1;
      this.warmingService.recordAccess({ key: baseKey, timestamp: nowMs() });
      try {
        const parsed = JSON.parse(l2Raw) as T;
        this.setL1(effective, parsed, ttlSeconds);
        return parsed;
      } catch {
        // fall through to fetcher
      }
    }
    this.warmingService.recordAccess({ key: baseKey, timestamp: nowMs() });

    this.stats.misses += 1;
    const promise = fetcher()
      .then((value) => {
        const payload = JSON.stringify(value);
        redis.set(`cache:l2:${effective}`, payload, 'EX', ttlSeconds).catch(() => undefined);
        this.setL1(effective, value, ttlSeconds);
        this.stats.sets += 1;
        return value;
      })
      .finally(() => {
        this.inflight.delete(effective);
      });

    this.inflight.set(effective, promise);
    return (await promise) as T;
  }

  /**
   * Read-through pattern:
   * on L1/L2 miss, calls the fetcher and writes the result to both tiers.
   */
  async readThrough<T>(
    baseKey: string,
    fetcher: () => Promise<T>,
    options: CacheOptions<T> = {},
    tags: string[] = [],
  ): Promise<T> {
    return this.getOrSet(baseKey, fetcher, options, tags);
  }

  async get<T>(
    baseKey: string,
    options: CacheOptions<T> = {},
    tags: string[] = [],
  ): Promise<T | null> {
    const ttlSeconds = this.l1TtlSeconds(options);
    const effective = await this.effectiveKey(baseKey, tags);

    const l1Value = this.getL1(effective);
    if (l1Value !== undefined) {
      this.stats.l1Hits += 1;
      return l1Value as T;
    }

    const redis = this.redisService.getClient();
    const l2Raw = await redis.get(`cache:l2:${effective}`);
    if (l2Raw === null || l2Raw === undefined) return null;

    try {
      const parsed = JSON.parse(l2Raw) as T;
      this.setL1(effective, parsed, ttlSeconds);
      this.stats.l2Hits += 1;
      return parsed;
    } catch {
      return null;
    }
  }

  async set<T>(
    baseKey: string,
    value: T,
    options: CacheOptions<T> = {},
    tags: string[] = [],
  ): Promise<void> {
    const ttlSeconds = this.l1TtlSeconds(options);
    const effective = await this.effectiveKey(baseKey, tags);
    const redis = this.redisService.getClient();

    await Promise.all([
      redis.set(`cache:l2:${effective}`, JSON.stringify(value), 'EX', ttlSeconds),
      Promise.resolve(this.setL1(effective, value, ttlSeconds)),
    ]);
    this.stats.sets += 1;
  }

  /**
   * Cache warming: proactively fetch + populate caches.
   * This leverages the same single-flight protection as `getOrSet`.
   */
  async warm<T>(
    baseKey: string,
    fetcher: () => Promise<T>,
    options: CacheOptions<T> = {},
    tags: string[] = [],
  ): Promise<T> {
    return this.getOrSet(baseKey, fetcher, options, tags);
  }

  /**
   * Cache write-through + tag invalidation helper.
   * - writes value to caches
   * - optionally invalidates related tags
   */
  async writeThrough<T>(
    baseKey: string,
    value: T,
    options: CacheOptions<T> = {},
    tags: string[] = [],
    invalidateRelatedTags: string[] = [],
  ): Promise<void> {
    await this.set(baseKey, value, options, tags);
    if (invalidateRelatedTags?.length) await this.invalidateTags(invalidateRelatedTags);
  }

  getAnalytics(): CacheStats & { totalRequests: number; hitRate: number; evictionRate: number } {
    const totalRequests = this.stats.l1Hits + this.stats.l2Hits + this.stats.misses;
    const hitRate = totalRequests ? (this.stats.l1Hits + this.stats.l2Hits) / totalRequests : 0;
    const evictionRate = totalRequests ? this.stats.evictions / totalRequests : 0;
    return { ...this.stats, totalRequests, hitRate, evictionRate };
  }
}
