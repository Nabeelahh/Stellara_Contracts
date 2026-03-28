import { BadRequestException, HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { NotificationService } from '../notification/services/notification.service';
import { PrismaService } from '../prisma.service';
import { RedisService } from '../redis/redis.service';
import type { Request } from 'express';
import { NotificationType, type ApiOveragePolicy } from '@prisma/client';

function getPeriodKey(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

function getSecondsUntilUtcMonthEnd(now: Date): number {
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  // First day of next month at 00:00 UTC
  const nextMonth = new Date(Date.UTC(year, month + 1, 1, 0, 0, 0));
  const diffMs = nextMonth.getTime() - now.getTime();
  return Math.max(1, Math.ceil(diffMs / 1000));
}

type TenantUsage = {
  tenantId: string;
  period: string;
  apiCallsUsed: number;
  apiCallsPerMonthLimit: number;
  storageUsedGb: number;
  storageGbLimit: number;
  usersUsed: number;
  maxUsers: number;
  apiOveragePolicy: ApiOveragePolicy;
};

@Injectable()
export class TenantQuotaService {
  private readonly logger = new Logger(TenantQuotaService.name);
  private readonly activeTenantsSetKey = 'quota:active-tenants';
  private readonly limitsCacheTtlSeconds = 60;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
    private readonly notificationService: NotificationService,
  ) {}

  getTenantIdFromRequest(req: Request): string | undefined {
    const headerTenantId = req.headers['x-tenant-id'];
    if (typeof headerTenantId === 'string' && headerTenantId.trim()) return headerTenantId.trim();

    const queryTenantId = req.query?.tenantId;
    if (typeof queryTenantId === 'string' && queryTenantId.trim()) return queryTenantId.trim();

    return undefined;
  }

  private apiUsageKey(tenantId: string, period: string): string {
    return `quota:${tenantId}:${period}:api_calls_used`;
  }

  private warnKey(tenantId: string, period: string, level: 'warn80' | 'warn95'): string {
    return `quota:${tenantId}:${period}:${level}_sent`;
  }

  private overageKey(tenantId: string, period: string): string {
    return `quota:${tenantId}:${period}:overage_billed_sent`;
  }

  private async getTenantLimits(tenantId: string): Promise<{
    apiCallsPerMonthLimit: number;
    storageGbLimit: number;
    apiOveragePolicy: ApiOveragePolicy;
    maxUsers: number;
  }> {
    // Cache limits briefly in Redis to avoid hitting Postgres on every request.
    const cacheKey = `quota:${tenantId}:limits`;
    const redis = this.redisService.getClient();

    const cached = await redis.get(cacheKey);
    if (cached) {
      try {
        return JSON.parse(cached) as any;
      } catch {
        // ignore cache corruption
      }
    }

    const settings = await this.prisma.tenantSettings.findUnique({
      where: { tenantId },
      select: {
        apiCallsPerMonthLimit: true,
        storageGbLimit: true,
        apiOveragePolicy: true,
        maxUsers: true,
      },
    });

    if (!settings) {
      throw new BadRequestException(`Missing tenant quota settings for tenant ${tenantId}`);
    }

    const result = {
      apiCallsPerMonthLimit: Number(settings.apiCallsPerMonthLimit),
      storageGbLimit: Number(settings.storageGbLimit),
      apiOveragePolicy: settings.apiOveragePolicy as ApiOveragePolicy,
      maxUsers: Number(settings.maxUsers),
    };

    await redis.set(cacheKey, JSON.stringify(result), 'EX', this.limitsCacheTtlSeconds);
    return result;
  }

  async consumeApiCallOrThrow(
    tenantId: string,
  ): Promise<{ used: number; limit: number; period: string }> {
    const now = new Date();
    const period = getPeriodKey(now);
    const ttlSeconds = getSecondsUntilUtcMonthEnd(now);
    const redis = this.redisService.getClient();

    // Mark tenant active for scheduled cleanup.
    await redis.sadd(this.activeTenantsSetKey, tenantId);

    const limits = await this.getTenantLimits(tenantId);
    const limit = limits.apiCallsPerMonthLimit;

    if (!Number.isFinite(limit) || limit <= 0) {
      throw new BadRequestException(`Invalid API call limit for tenant ${tenantId}`);
    }

    const key = this.apiUsageKey(tenantId, period);
    const used = await redis.incr(key);
    if (used === 1) {
      await redis.expire(key, ttlSeconds);
    }

    // Threshold warnings
    const warn80 = Math.floor(limit * 0.8);
    const warn95 = Math.floor(limit * 0.95);

    if (warn80 > 0 && used >= warn80) {
      const didWarn80 = await redis.set(
        this.warnKey(tenantId, period, 'warn80'),
        '1',
        'EX',
        ttlSeconds,
        'NX',
      );
      if (didWarn80) {
        await this.sendQuotaWarning(tenantId, used, limit, '80%');
      }
    }

    if (warn95 > 0 && used >= warn95) {
      const didWarn95 = await redis.set(
        this.warnKey(tenantId, period, 'warn95'),
        '1',
        'EX',
        ttlSeconds,
        'NX',
      );
      if (didWarn95) {
        await this.sendQuotaWarning(tenantId, used, limit, '95%');
      }
    }

    // Hard stop vs overage billing
    if (used > limit) {
      if (limits.apiOveragePolicy === 'HARD_STOP') {
        throw new HttpException(
          {
            message: 'Tenant API quota exceeded',
            tenantId,
            period,
            used,
            limit,
          },
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      // BILL_OVERAGE: allow but notify once per month.
      const didOverage = await redis.set(
        this.overageKey(tenantId, period),
        '1',
        'EX',
        ttlSeconds,
        'NX',
      );
      if (didOverage) {
        await this.sendQuotaOverage(tenantId, used, limit);
      }
    }

    return { used, limit, period };
  }

  async getTenantUsage(tenantId: string): Promise<TenantUsage> {
    const now = new Date();
    const period = getPeriodKey(now);
    const redis = this.redisService.getClient();

    const limits = await this.getTenantLimits(tenantId);
    const usedStr = await redis.get(this.apiUsageKey(tenantId, period));
    const apiCallsUsed = usedStr ? Number(usedStr) : 0;

    // Storage tracking isn’t wired in the repo yet; return 0 until integrated.
    const storageUsedGb = 0;

    const usersUsed = await this.prisma.user.count({ where: { tenantId } });

    return {
      tenantId,
      period,
      apiCallsUsed,
      apiCallsPerMonthLimit: limits.apiCallsPerMonthLimit,
      storageUsedGb,
      storageGbLimit: limits.storageGbLimit,
      usersUsed,
      maxUsers: limits.maxUsers,
      apiOveragePolicy: limits.apiOveragePolicy,
    };
  }

  private async sendQuotaWarning(
    tenantId: string,
    used: number,
    limit: number,
    thresholdLabel: string,
  ): Promise<void> {
    // Find the tenant admin to notify.
    const adminUser = await this.prisma.user.findFirst({
      where: { tenantId, roles: { has: 'TENANT_ADMIN' } },
      select: { id: true },
    });

    if (!adminUser) {
      this.logger.warn(`No tenant admin found for tenant ${tenantId}, cannot send quota warning`);
      return;
    }

    await this.notificationService.notify(
      adminUser.id,
      NotificationType.SYSTEM,
      `Quota warning: ${thresholdLabel}`,
      `Your tenant has reached ${thresholdLabel} of its monthly API quota. Used: ${used}, Limit: ${limit}. Period: ${getPeriodKey(
        new Date(),
      )}`,
      { tenantId, used, limit, thresholdLabel },
    );
  }

  private async sendQuotaOverage(tenantId: string, used: number, limit: number): Promise<void> {
    const adminUser = await this.prisma.user.findFirst({
      where: { tenantId, roles: { has: 'TENANT_ADMIN' } },
      select: { id: true },
    });

    if (!adminUser) return;

    await this.notificationService.notify(
      adminUser.id,
      NotificationType.SYSTEM,
      'Quota overage notice',
      `Your tenant exceeded its monthly API quota. Used: ${used}, Limit: ${limit}.`,
      { tenantId, used, limit },
    );
  }

  /**
   * Monthly reset job.
   * We rely primarily on Redis TTL, but also eagerly delete counters for active tenants
   * to satisfy the “monthly reset automation” acceptance criteria.
   */
  @Cron('0 0 1 * *')
  async monthlyReset(): Promise<void> {
    const redis = this.redisService.getClient();
    const now = new Date();

    // Reset previous month counters for active tenants.
    const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1, 0, 0, 0));
    const prevPeriod = getPeriodKey(prev);

    const tenantIds = await redis.smembers(this.activeTenantsSetKey);
    if (!tenantIds.length) return;

    // Best-effort cleanup; Redis TTL will also expire keys automatically.
    const pipeline = redis.pipeline();
    for (const tenantId of tenantIds) {
      pipeline.del(this.apiUsageKey(tenantId, prevPeriod));
      pipeline.del(this.warnKey(tenantId, prevPeriod, 'warn80'));
      pipeline.del(this.warnKey(tenantId, prevPeriod, 'warn95'));
      pipeline.del(this.overageKey(tenantId, prevPeriod));
    }
    await pipeline.exec();

    this.logger.log(
      `Monthly quota reset complete for ${tenantIds.length} tenants (period ${prevPeriod}).`,
    );
  }
}
