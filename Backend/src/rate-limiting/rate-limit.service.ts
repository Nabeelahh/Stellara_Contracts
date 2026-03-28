import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Job, Queue, QueueEvents, Worker, DelayedError } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { Request } from 'express';
import { RedisService } from '../redis/redis.service';
import { ApplicationStateService } from '../lifecycle/application-state.service';
import { parseDurationToMilliseconds } from '../common/utils/duration.util';

type RateLimitTier = 'free' | 'pro' | 'enterprise';

interface TierPolicy {
  tier: RateLimitTier;
  limitPerMinute: number;
  burstCapacity: number;
  priority: number;
}

interface BucketResult {
  allowed: boolean;
  remainingTokens: number;
  retryAfterMs: number;
}

interface QueueJobData {
  bucketKey: string;
  requestedAt: number;
  refillPerMs: number;
  capacity: number;
}

interface RateLimitIdentity {
  id?: string;
  roles?: string[];
  subscriptionTier?: string;
}

const TOKEN_BUCKET_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local state = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

if tokens == nil then tokens = capacity end
if last_refill == nil then last_refill = now end

local elapsed = math.max(0, now - last_refill)
local refilled = math.min(capacity, tokens + (elapsed * refill_rate))

local allowed = 0
local retry_after = 0

if refilled >= cost then
  refilled = refilled - cost
  allowed = 1
elseif refill_rate > 0 then
  retry_after = math.ceil((cost - refilled) / refill_rate)
end

redis.call('HMSET', key, 'tokens', refilled, 'last_refill', now)
redis.call('PEXPIRE', key, ttl)

return {allowed, refilled, retry_after}
`;

@Injectable()
export class RateLimitService implements OnApplicationShutdown {
  private readonly logger = new Logger(RateLimitService.name);
  private readonly queueName = 'rate-limit-requests';
  private readonly queueTimeoutMs = parseDurationToMilliseconds(
    process.env.RATE_LIMIT_QUEUE_TIMEOUT_MS,
    15_000,
  );
  private readonly burstMultiplier = Number(process.env.RATE_LIMIT_BURST_MULTIPLIER || '1.5');
  private readonly bucketTtlMs = parseDurationToMilliseconds(
    process.env.RATE_LIMIT_BUCKET_TTL_MS,
    120_000,
  );

  private readonly queue: Queue<QueueJobData>;
  private readonly queueEvents: QueueEvents;
  private readonly worker: Worker<QueueJobData, BucketResult>;

  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly appState: ApplicationStateService,
  ) {
    const connection = this.redisService.getBullConnection();

    this.queue = new Queue<QueueJobData>(this.queueName, { connection });
    this.queueEvents = new QueueEvents(this.queueName, { connection });
    this.worker = new Worker<QueueJobData, BucketResult>(
      this.queueName,
      async (job) => this.processQueuedRequest(job),
      {
        connection,
        concurrency: parseInt(process.env.RATE_LIMIT_QUEUE_CONCURRENCY || '50', 10),
      },
    );
  }

  async acquire(req: Request): Promise<void> {
    const identity = await this.resolveIdentity(req);
    const policy = this.buildPolicy(req, identity);
    const bucketKey = this.getBucketKey(req, identity);
    const refillPerMs = policy.limitPerMinute / 60_000;

    const immediate = await this.consumeBucket(bucketKey, refillPerMs, policy.burstCapacity, 1);

    if (immediate.allowed) {
      return;
    }

    const job = await this.queue.add(
      'queued-request',
      {
        bucketKey,
        requestedAt: Date.now(),
        refillPerMs,
        capacity: policy.burstCapacity,
      },
      {
        jobId: randomUUID(),
        priority: policy.priority,
        removeOnComplete: 1_000,
        removeOnFail: 1_000,
      },
    );

    try {
      await job.waitUntilFinished(this.queueEvents, this.queueTimeoutMs);
    } catch (error) {
      await job.remove().catch(() => undefined);

      throw new HttpException(
        {
          message: 'Request exceeded rate limit queue timeout',
          retryAfterMs: immediate.retryAfterMs,
          queueTimeoutMs: this.queueTimeoutMs,
          tier: policy.tier,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  async getStatus(req: Request) {
    const identity = await this.resolveIdentity(req);
    const policy = this.buildPolicy(req, identity);
    const bucketKey = this.getBucketKey(req, identity);
    const refillPerMs = policy.limitPerMinute / 60_000;
    const snapshot = await this.consumeBucket(bucketKey, refillPerMs, policy.burstCapacity, 0);
    const queueCounts = await this.queue.getJobCounts(
      'waiting',
      'active',
      'delayed',
      'prioritized',
      'completed',
      'failed',
    );

    return {
      tier: policy.tier,
      effectiveLimitPerMinute: policy.limitPerMinute,
      burstCapacity: policy.burstCapacity,
      queueTimeoutMs: this.queueTimeoutMs,
      adaptiveLoadFactor: this.appState.getAdaptiveLoadFactor(),
      remainingTokens: snapshot.remainingTokens,
      retryAfterMs: snapshot.retryAfterMs,
      queue: queueCounts,
    };
  }

  async onApplicationShutdown(): Promise<void> {
    await this.worker.close().catch(() => undefined);
    await this.queueEvents.close().catch(() => undefined);
    await this.queue.close().catch(() => undefined);
  }

  private async processQueuedRequest(job: Job<QueueJobData>): Promise<BucketResult> {
    const result = await this.consumeBucket(
      job.data.bucketKey,
      job.data.refillPerMs,
      job.data.capacity,
      1,
    );

    if (!result.allowed) {
      await job.moveToDelayed(Date.now() + Math.max(result.retryAfterMs, 50), job.token);
      throw new DelayedError();
    }

    return result;
  }

  private buildPolicy(req: Request, identity: RateLimitIdentity): TierPolicy {
    const tier = this.resolveTier(req, identity);
    const baseLimit = tier === 'enterprise' ? 2000 : tier === 'pro' ? 500 : 100;
    const adaptiveLimit = Math.max(
      10,
      Math.floor(baseLimit * this.appState.getAdaptiveLoadFactor()),
    );

    return {
      tier,
      limitPerMinute: adaptiveLimit,
      burstCapacity: Math.max(adaptiveLimit, Math.round(adaptiveLimit * this.burstMultiplier)),
      priority: tier === 'enterprise' ? 1 : tier === 'pro' ? 5 : 10,
    };
  }

  private resolveTier(req: Request, identity: RateLimitIdentity): RateLimitTier {
    const headerTier = String(req.headers['x-subscription-tier'] || '').toLowerCase();
    if (headerTier === 'free' || headerTier === 'pro' || headerTier === 'enterprise') {
      return headerTier;
    }

    const userRoles = identity.roles || req.user?.roles || [];
    if (identity.subscriptionTier === 'enterprise') {
      return 'enterprise';
    }
    if (identity.subscriptionTier === 'pro') {
      return 'pro';
    }
    if (userRoles.includes('SUPER_ADMIN')) {
      return 'enterprise';
    }
    if (userRoles.includes('TENANT_ADMIN')) {
      return 'pro';
    }

    return 'free';
  }

  private getBucketKey(req: Request, identity: RateLimitIdentity): string {
    if (identity.id || req.user?.id) {
      return `rate-limit:user:${identity.id || req.user?.id}`;
    }

    const ip =
      req.ip ||
      String(req.headers['x-forwarded-for'] || '')
        .split(',')[0]
        .trim() ||
      'anonymous';

    return `rate-limit:ip:${ip}`;
  }

  private async resolveIdentity(req: Request): Promise<RateLimitIdentity> {
    if (req.user?.id || req.user?.roles || req.user?.subscriptionTier) {
      return {
        id: req.user?.id,
        roles: req.user?.roles,
        subscriptionTier: req.user?.subscriptionTier,
      };
    }

    const token = this.extractToken(req);
    if (!token) {
      return {};
    }

    try {
      const payload = await this.jwtService.verifyAsync<{
        sub?: string;
        roles?: string[];
        subscriptionTier?: string;
      }>(token, {
        secret: this.configService.get<string>('JWT_SECRET', 'super_secret_key_for_development'),
      });

      return {
        id: payload.sub,
        roles: payload.roles,
        subscriptionTier: payload.subscriptionTier,
      };
    } catch {
      return {};
    }
  }

  private extractToken(req: Request): string | null {
    const cookieToken = req.cookies?.['access_token'];
    if (cookieToken) {
      return cookieToken;
    }

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }

    return null;
  }

  private async consumeBucket(
    bucketKey: string,
    refillPerMs: number,
    capacity: number,
    cost: number,
  ): Promise<BucketResult> {
    const now = Date.now();
    const [allowed, remainingTokens, retryAfterMs] = (await this.redisService
      .getClient()
      .eval(
        TOKEN_BUCKET_SCRIPT,
        1,
        bucketKey,
        now,
        refillPerMs,
        capacity,
        cost,
        this.bucketTtlMs,
      )) as [number, number, number];

    return {
      allowed: allowed === 1,
      remainingTokens: Math.max(0, Number(remainingTokens || 0)),
      retryAfterMs: Math.max(0, Number(retryAfterMs || 0)),
    };
  }
}
