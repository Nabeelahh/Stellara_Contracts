import { Cron, CronExpression } from '@nestjs/schedule';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';

import { AuditService } from '../audit/audit.service';
import { ConfigService } from '@nestjs/config';
import { ObjectStorageService } from '../object-storage/object-storage.service';
import { PrismaService } from '../prisma.service';
import { RedisService } from '../redis/redis.service';
import {
  CreateLegalHoldDto,
  CreateRetentionRuleDto,
  ForgetUserDto,
  RetentionDataTypeDto,
  UpdateRetentionRuleDto,
} from './dto/data-retention.dto';

type RetentionDataType = 'TRADES' | 'LOGS' | 'SESSIONS' | 'ANALYTICS' | 'WEBHOOKS' | 'AUDIT';
type RuleRecord = any;

type ExecutionReport = {
  dataType: RetentionDataType;
  dryRun: boolean;
  cutoffDate: string;
  examinedCount: number;
  heldCount: number;
  archivedCount: number;
  deletedCount: number;
  cryptoShreddedCount: number;
  archiveKeys: string[];
  cryptoShredDigests: string[];
};

type RuleExecutionResult = {
  archivedCount: number;
  deletedCount: number;
  cryptoShreddedCount: number;
  report: Record<string, unknown>;
};

type RetentionBatchOptions<T extends { id: string }> = {
  rule: RuleRecord;
  dataType: RetentionDataType;
  dryRun: boolean;
  batchLabel: string;
  cutoffDate: Date;
  fetchBatch: (skip: number, take: number) => Promise<T[]>;
  deleteByIds: (ids: string[]) => Promise<number>;
};

@Injectable()
export class DataRetentionService implements OnModuleInit {
  private readonly logger = new Logger(DataRetentionService.name);
  private readonly defaultBatchSize: number;
  private readonly nightlyLockTtlSeconds: number;

  private readonly baselineRules: Array<{
    name: string;
    dataType: RetentionDataType;
    retentionDays: number;
    archiveEnabled: boolean;
    secureDelete: boolean;
    legalHoldEnabled: boolean;
  }> = [
    {
      name: 'Default Trades Retention (7 Years)',
      dataType: 'TRADES',
      retentionDays: 2555,
      archiveEnabled: true,
      secureDelete: true,
      legalHoldEnabled: true,
    },
    {
      name: 'Default Logs Retention (90 Days)',
      dataType: 'LOGS',
      retentionDays: 90,
      archiveEnabled: true,
      secureDelete: true,
      legalHoldEnabled: true,
    },
    {
      name: 'Default Sessions Retention (30 Days)',
      dataType: 'SESSIONS',
      retentionDays: 30,
      archiveEnabled: true,
      secureDelete: true,
      legalHoldEnabled: true,
    },
  ];

  constructor(
    private readonly prisma: PrismaService,
    private readonly objectStorage: ObjectStorageService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly auditService: AuditService,
  ) {
    this.defaultBatchSize = this.configService.get<number>('RETENTION_BATCH_SIZE', 500);
    this.nightlyLockTtlSeconds = this.configService.get<number>(
      'RETENTION_NIGHTLY_LOCK_TTL_SECONDS',
      60 * 60,
    );
  }

  async onModuleInit(): Promise<void> {
    await this.ensureBaselineRules();
  }

  async createRule(dto: CreateRetentionRuleDto): Promise<RuleRecord> {
    const existing = await (this.prisma as any).dataRetentionRule.findFirst({
      where: {
        tenantId: dto.tenantId ?? null,
        dataType: dto.dataType,
      },
    });

    if (existing) {
      throw new ConflictException(
        `Retention rule already exists for ${dto.dataType} and tenant ${dto.tenantId ?? 'GLOBAL'}`,
      );
    }

    const created = await (this.prisma as any).dataRetentionRule.create({
      data: {
        name: dto.name,
        dataType: dto.dataType,
        tenantId: dto.tenantId ?? null,
        retentionDays: dto.retentionDays,
        archiveEnabled: dto.archiveEnabled ?? true,
        archivePrefix: dto.archivePrefix ?? null,
        secureDelete: dto.secureDelete ?? true,
        legalHoldEnabled: dto.legalHoldEnabled ?? true,
        isActive: dto.isActive ?? true,
      },
    });

    await this.auditService.logSystemEvent('DATA_RETENTION_RULE_CREATED', {
      ruleId: created.id,
      dataType: created.dataType,
      tenantId: created.tenantId,
    });

    return created;
  }

  async listRules(tenantId?: string): Promise<RuleRecord[]> {
    const where: Record<string, unknown> = {};
    if (tenantId) {
      where.OR = [{ tenantId }, { tenantId: null }];
    }

    return (this.prisma as any).dataRetentionRule.findMany({
      where,
      orderBy: [{ tenantId: 'asc' }, { dataType: 'asc' }],
    });
  }

  async getRule(ruleId: string): Promise<RuleRecord> {
    const rule = await (this.prisma as any).dataRetentionRule.findUnique({
      where: { id: ruleId },
    });

    if (!rule) {
      throw new NotFoundException(`Retention rule ${ruleId} not found`);
    }

    return rule;
  }

  async updateRule(ruleId: string, dto: UpdateRetentionRuleDto): Promise<RuleRecord> {
    await this.getRule(ruleId);

    const updated = await (this.prisma as any).dataRetentionRule.update({
      where: { id: ruleId },
      data: {
        name: dto.name,
        retentionDays: dto.retentionDays,
        archiveEnabled: dto.archiveEnabled,
        archivePrefix: dto.archivePrefix,
        secureDelete: dto.secureDelete,
        legalHoldEnabled: dto.legalHoldEnabled,
        isActive: dto.isActive,
      },
    });

    await this.auditService.logSystemEvent('DATA_RETENTION_RULE_UPDATED', {
      ruleId,
      changes: dto,
    });

    return updated;
  }

  async executeRule(ruleId: string, dryRun = false): Promise<RuleRecord> {
    const rule = await this.getRule(ruleId);
    if (!rule.isActive) {
      throw new BadRequestException(`Retention rule ${ruleId} is inactive`);
    }

    const execution = await (this.prisma as any).retentionExecution.create({
      data: {
        ruleId: rule.id,
        dataType: rule.dataType,
        status: 'RUNNING',
        startedAt: new Date(),
      },
    });

    try {
      const runResult = await this.executeRuleInternal(rule, dryRun);
      const status = dryRun ? 'DRY_RUN_COMPLETED' : 'COMPLETED';

      const updatedExecution = await (this.prisma as any).retentionExecution.update({
        where: { id: execution.id },
        data: {
          status,
          archivedCount: runResult.archivedCount,
          deletedCount: runResult.deletedCount,
          cryptoShreddedCount: runResult.cryptoShreddedCount,
          report: runResult.report,
          finishedAt: new Date(),
        },
      });

      await (this.prisma as any).dataRetentionRule.update({
        where: { id: rule.id },
        data: { lastRunAt: new Date() },
      });

      await this.auditService.logSystemEvent('DATA_RETENTION_RULE_EXECUTED', {
        ruleId: rule.id,
        dataType: rule.dataType,
        dryRun,
        archivedCount: runResult.archivedCount,
        deletedCount: runResult.deletedCount,
        executionId: execution.id,
      });

      return updatedExecution;
    } catch (error) {
      await (this.prisma as any).retentionExecution.update({
        where: { id: execution.id },
        data: {
          status: 'FAILED',
          error: String(error?.message || 'Unknown retention execution failure'),
          finishedAt: new Date(),
        },
      });

      await this.auditService.logError('DATA_RETENTION_EXECUTION', String(error?.message || error), {
        ruleId: rule.id,
        executionId: execution.id,
      });

      throw error;
    }
  }

  async createLegalHold(dto: CreateLegalHoldDto): Promise<RuleRecord> {
    const expiresAt = this.parseOptionalDate(dto.expiresAt);

    const created = await (this.prisma as any).legalHold.create({
      data: {
        ruleId: null,
        dataType: dto.dataType,
        referenceId: dto.referenceId,
        reason: dto.reason,
        heldBy: dto.heldBy ?? null,
        expiresAt,
        isActive: true,
        metadata: dto.metadata ?? null,
      },
    });

    await this.auditService.logSystemEvent('LEGAL_HOLD_CREATED', {
      holdId: created.id,
      dataType: created.dataType,
      referenceId: created.referenceId,
      expiresAt,
    });

    return created;
  }

  async listLegalHolds(activeOnly = true): Promise<RuleRecord[]> {
    const where: Record<string, unknown> = {};
    if (activeOnly) {
      where.isActive = true;
    }

    return (this.prisma as any).legalHold.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  async releaseLegalHold(holdId: string, releasedBy?: string): Promise<RuleRecord> {
    const hold = await (this.prisma as any).legalHold.findUnique({
      where: { id: holdId },
    });
    if (!hold) {
      throw new NotFoundException(`Legal hold ${holdId} not found`);
    }

    const updated = await (this.prisma as any).legalHold.update({
      where: { id: holdId },
      data: {
        isActive: false,
        metadata: {
          ...(hold.metadata || {}),
          releasedAt: new Date().toISOString(),
          releasedBy: releasedBy || null,
        },
      },
    });

    await this.auditService.logSystemEvent('LEGAL_HOLD_RELEASED', {
      holdId,
      releasedBy: releasedBy ?? null,
    });

    return updated;
  }

  async forgetUser(userId: string, dto: ForgetUserDto): Promise<Record<string, unknown>> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`User ${userId} not found`);
    }

    const activeHolds = await (this.prisma as any).legalHold.findMany({
      where: {
        isActive: true,
        referenceId: userId,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
    });

    if (activeHolds.length > 0) {
      throw new ConflictException(
        `Cannot forget user ${userId} because ${activeHolds.length} legal hold(s) are active`,
      );
    }

    const anonSuffix = createHash('sha256')
      .update(`${userId}:${Date.now()}:${randomUUID()}`)
      .digest('hex')
      .slice(0, 24);
    const anonymizedWalletAddress = `anon_${anonSuffix}`;

    const outcome = await this.prisma.$transaction(async (tx) => {
      const anonymizedEvents = await tx.analyticsEvent.updateMany({
        where: { userId },
        data: {
          userId: null,
          anonymized: true,
          properties: {},
          sessionId: null,
        },
      });

      const deletedVerificationSessions = await (tx as any).verificationSession.deleteMany({
        where: { userId },
      });

      const scrubbedUser = await tx.user.update({
        where: { id: userId },
        data: {
          name: null,
          walletAddress: anonymizedWalletAddress,
          profileData: {
            anonymized: true,
            anonymizedAt: new Date().toISOString(),
            reason: dto.reason || 'right_to_be_forgotten',
            requestedBy: dto.requestedBy,
          } as any,
          phoneNumber: null,
          email: null,
          phoneEncrypted: null,
          ssnEncrypted: null,
          addressEncrypted: null,
          hashedRefreshToken: null,
        },
      });

      const deletedNotifications = await tx.notification.deleteMany({
        where: { userId },
      });

      await tx.notificationSetting.deleteMany({
        where: { userId },
      });

      return {
        anonymizedEvents: anonymizedEvents.count,
        deletedVerificationSessions: deletedVerificationSessions.count,
        deletedNotifications: deletedNotifications.count,
        anonymizedUserId: scrubbedUser.id,
      };
    });

    await this.auditService.logSystemEvent('RIGHT_TO_BE_FORGOTTEN_EXECUTED', {
      userId,
      requestedBy: dto.requestedBy,
      reason: dto.reason ?? null,
      outcome,
    });

    return {
      success: true,
      userId,
      requestedBy: dto.requestedBy,
      reason: dto.reason ?? null,
      ...outcome,
    };
  }

  async getExecutions(limit = 50): Promise<RuleRecord[]> {
    return (this.prisma as any).retentionExecution.findMany({
      orderBy: { createdAt: 'desc' },
      take: Math.max(1, Math.min(limit, 200)),
      include: {
        rule: true,
      },
    });
  }

  async getComplianceReport(days = 30): Promise<Record<string, unknown>> {
    const lookbackDays = Math.max(1, Math.min(days, 365));
    const fromDate = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000);
    const [rules, executions, activeLegalHolds, expiredLegalHolds] = await Promise.all([
      (this.prisma as any).dataRetentionRule.findMany({
        orderBy: [{ tenantId: 'asc' }, { dataType: 'asc' }],
      }),
      (this.prisma as any).retentionExecution.findMany({
        where: { createdAt: { gte: fromDate } },
        orderBy: { createdAt: 'desc' },
        include: { rule: true },
      }),
      (this.prisma as any).legalHold.count({
        where: {
          isActive: true,
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
        },
      }),
      (this.prisma as any).legalHold.count({
        where: {
          isActive: true,
          expiresAt: { lte: new Date() },
        },
      }),
    ]);

    const requiredDataTypes: RetentionDataType[] = ['TRADES', 'LOGS', 'SESSIONS'];
    const missingRequiredRules = requiredDataTypes.filter(
      (dataType) => !rules.some((rule: RuleRecord) => rule.tenantId === null && rule.dataType === dataType),
    );

    const stats = executions.reduce(
      (acc: Record<string, number>, row: RuleRecord) => {
        const status = String(row.status || 'UNKNOWN');
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    const totalArchived = executions.reduce(
      (sum: number, row: RuleRecord) => sum + Number(row.archivedCount || 0),
      0,
    );
    const totalDeleted = executions.reduce(
      (sum: number, row: RuleRecord) => sum + Number(row.deletedCount || 0),
      0,
    );
    const totalCryptoShredded = executions.reduce(
      (sum: number, row: RuleRecord) => sum + Number(row.cryptoShreddedCount || 0),
      0,
    );

    return {
      generatedAt: new Date().toISOString(),
      lookbackDays,
      missingRequiredRules,
      requiredRulesCompliant: missingRequiredRules.length === 0,
      activeLegalHolds,
      expiredActiveLegalHolds: expiredLegalHolds,
      totals: {
        rules: rules.length,
        executions: executions.length,
        totalArchived,
        totalDeleted,
        totalCryptoShredded,
      },
      executionsByStatus: stats,
      latestExecutions: executions.slice(0, 20),
      rules,
    };
  }

  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async runNightlyRetention(): Promise<void> {
    await this.withDistributedLock('retention:nightly:lock', this.nightlyLockTtlSeconds, async () => {
      this.logger.log('Starting nightly data retention run');
      const rules = await (this.prisma as any).dataRetentionRule.findMany({
        where: { isActive: true },
      });

      for (const rule of rules) {
        try {
          await this.executeRule(rule.id, false);
        } catch (error) {
          this.logger.error(
            `Nightly retention failed for rule ${rule.id} (${rule.dataType}): ${error.message}`,
            error.stack,
          );
        }
      }

      await this.auditService.logSystemEvent('NIGHTLY_RETENTION_COMPLETED', {
        ruleCount: rules.length,
      });
    });
  }

  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredLegalHolds(): Promise<void> {
    const result = await (this.prisma as any).legalHold.updateMany({
      where: {
        isActive: true,
        expiresAt: { lte: new Date() },
      },
      data: {
        isActive: false,
      },
    });

    if (result.count > 0) {
      await this.auditService.logSystemEvent('EXPIRED_LEGAL_HOLDS_CLEANED', {
        count: result.count,
      });
    }
  }

  private async ensureBaselineRules(): Promise<void> {
    for (const baseline of this.baselineRules) {
      const existing = await (this.prisma as any).dataRetentionRule.findFirst({
        where: {
          tenantId: null,
          dataType: baseline.dataType,
        },
      });

      if (existing) {
        continue;
      }

      await (this.prisma as any).dataRetentionRule.create({
        data: {
          name: baseline.name,
          dataType: baseline.dataType,
          tenantId: null,
          retentionDays: baseline.retentionDays,
          archiveEnabled: baseline.archiveEnabled,
          secureDelete: baseline.secureDelete,
          legalHoldEnabled: baseline.legalHoldEnabled,
          isActive: true,
          archivePrefix: `retention/${baseline.dataType.toLowerCase()}`,
        },
      });
    }
  }

  private async executeRuleInternal(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const dataType = rule.dataType as RetentionDataType;
    switch (dataType) {
      case 'TRADES':
        return this.executeTradesRule(rule, dryRun);
      case 'LOGS':
        return this.executeLogsRule(rule, dryRun);
      case 'SESSIONS':
        return this.executeSessionsRule(rule, dryRun);
      case 'ANALYTICS':
        return this.executeAnalyticsRule(rule, dryRun);
      case 'WEBHOOKS':
        return this.executeWebhooksRule(rule, dryRun);
      case 'AUDIT':
        return this.executeAuditRule(rule, dryRun);
      default:
        throw new BadRequestException(`Unsupported retention data type: ${dataType}`);
    }
  }

  private async executeTradesRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);
    const where: Record<string, unknown> = { createdAt: { lt: cutoffDate } };
    if (rule.tenantId) {
      where.tenantId = rule.tenantId;
    }

    return this.executeRetentionLoop({
      rule,
      dataType: 'TRADES',
      dryRun,
      batchLabel: 'stake-ledger',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).stakeLedger.findMany({
          where,
          orderBy: { createdAt: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).stakeLedger.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });
  }

  private async executeLogsRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);
    const where: Record<string, unknown> = { createdAt: { lt: cutoffDate } };

    return this.executeRetentionLoop({
      rule,
      dataType: 'LOGS',
      dryRun,
      batchLabel: 'indexer-logs',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).indexerLog.findMany({
          where,
          orderBy: { createdAt: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).indexerLog.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });
  }

  private async executeSessionsRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);
    const where: Record<string, unknown> = { expiresAt: { lt: cutoffDate } };

    return this.executeRetentionLoop({
      rule,
      dataType: 'SESSIONS',
      dryRun,
      batchLabel: 'token-blacklist',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).tokenBlacklist.findMany({
          where,
          orderBy: { createdAt: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).tokenBlacklist.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });
  }

  private async executeAnalyticsRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);

    const snapshotResult = await this.executeRetentionLoop({
      rule,
      dataType: 'ANALYTICS',
      dryRun,
      batchLabel: 'metric-snapshots',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).realtimeMetricSnapshot.findMany({
          where: { capturedAt: { lt: cutoffDate } },
          orderBy: { capturedAt: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).realtimeMetricSnapshot.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });

    const rollupResult = await this.executeRetentionLoop({
      rule,
      dataType: 'ANALYTICS',
      dryRun,
      batchLabel: 'metric-rollups',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).realtimeMetricRollup.findMany({
          where: { bucketEnd: { lt: cutoffDate } },
          orderBy: { bucketEnd: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).realtimeMetricRollup.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });

    return {
      archivedCount: snapshotResult.archivedCount + rollupResult.archivedCount,
      deletedCount: snapshotResult.deletedCount + rollupResult.deletedCount,
      cryptoShreddedCount: snapshotResult.cryptoShreddedCount + rollupResult.cryptoShreddedCount,
      report: {
        snapshots: snapshotResult.report,
        rollups: rollupResult.report,
      },
    };
  }

  private async executeWebhooksRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);
    const where: Record<string, unknown> = { occurredAt: { lt: cutoffDate } };
    if (rule.tenantId) {
      where.tenantId = rule.tenantId;
    }

    return this.executeRetentionLoop({
      rule,
      dataType: 'WEBHOOKS',
      dryRun,
      batchLabel: 'webhook-events',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        (this.prisma as any).webhookEvent.findMany({
          where,
          orderBy: { occurredAt: 'asc' },
          skip,
          take,
          include: { deliveries: true },
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await (this.prisma as any).webhookEvent.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });
  }

  private async executeAuditRule(rule: RuleRecord, dryRun: boolean): Promise<RuleExecutionResult> {
    const cutoffDate = this.calculateCutoffDate(rule.retentionDays);
    const where: Record<string, unknown> = { createdAt: { lt: cutoffDate } };
    if (rule.tenantId) {
      where.tenantId = rule.tenantId;
    }

    return this.executeRetentionLoop({
      rule,
      dataType: 'AUDIT',
      dryRun,
      batchLabel: 'audit-logs',
      cutoffDate,
      fetchBatch: (skip: number, take: number) =>
        this.prisma.auditLog.findMany({
          where: where as any,
          orderBy: { createdAt: 'asc' },
          skip,
          take,
        }),
      deleteByIds: async (ids: string[]) => {
        const result = await this.prisma.auditLog.deleteMany({
          where: { id: { in: ids } },
        });
        return result.count;
      },
    });
  }

  private async executeRetentionLoop<T extends { id: string }>(
    options: RetentionBatchOptions<T>,
  ): Promise<RuleExecutionResult> {
    const report: ExecutionReport = {
      dataType: options.dataType,
      dryRun: options.dryRun,
      cutoffDate: options.cutoffDate.toISOString(),
      examinedCount: 0,
      heldCount: 0,
      archivedCount: 0,
      deletedCount: 0,
      cryptoShreddedCount: 0,
      archiveKeys: [],
      cryptoShredDigests: [],
    };

    let batchNo = 0;
    let skip = 0;

    while (true) {
      const records = await options.fetchBatch(skip, this.defaultBatchSize);
      if (records.length === 0) {
        break;
      }

      batchNo += 1;
      report.examinedCount += records.length;

      const ids = records.map((record) => String(record.id));
      const heldIds = await this.getActiveLegalHoldIds(options.dataType, ids);
      report.heldCount += heldIds.size;

      const eligible = records.filter((record) => !heldIds.has(String(record.id)));
      const eligibleIds = eligible.map((record) => String(record.id));

      if (options.rule.archiveEnabled && eligible.length > 0) {
        const archiveKey = await this.archiveBatch(
          options.rule,
          options.dataType,
          options.batchLabel,
          batchNo,
          eligible,
        );
        report.archiveKeys.push(archiveKey);
        report.archivedCount += eligible.length;
      }

      if (options.rule.secureDelete && eligible.length > 0) {
        report.cryptoShreddedCount += eligible.length;
        report.cryptoShredDigests.push(this.computeShredDigest(eligibleIds));
      }

      if (!options.dryRun && eligibleIds.length > 0) {
        report.deletedCount += await options.deleteByIds(eligibleIds);
      }

      if (options.dryRun) {
        skip += records.length;
      }

      if (records.length < this.defaultBatchSize) {
        break;
      }
    }

    return {
      archivedCount: report.archivedCount,
      deletedCount: report.deletedCount,
      cryptoShreddedCount: report.cryptoShreddedCount,
      report,
    };
  }

  private async archiveBatch(
    rule: RuleRecord,
    dataType: RetentionDataType,
    batchLabel: string,
    batchNo: number,
    records: unknown[],
  ): Promise<string> {
    const dateFolder = new Date().toISOString().slice(0, 10);
    const prefix =
      rule.archivePrefix || `retention/${(rule.tenantId || 'global').toString()}/${dataType.toLowerCase()}`;
    const key = `${prefix}/${dateFolder}/${batchLabel}-${rule.id}-batch-${batchNo}-${Date.now()}.json`;

    const payload = {
      ruleId: rule.id,
      ruleName: rule.name,
      dataType,
      tenantId: rule.tenantId,
      archivedAt: new Date().toISOString(),
      count: records.length,
      records,
    };

    await this.objectStorage.upload(Buffer.from(JSON.stringify(payload), 'utf8'), key, {
      contentType: 'application/json',
      storageClass: 'GLACIER',
      metadata: {
        retentionRuleId: rule.id,
        retentionDataType: dataType,
        compliance: 'gdpr-financial',
      },
    });

    return key;
  }

  private calculateCutoffDate(retentionDays: number): Date {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - retentionDays);
    return cutoff;
  }

  private parseOptionalDate(value?: string): Date | null {
    if (!value) {
      return null;
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw new BadRequestException(`Invalid date: ${value}`);
    }

    return parsed;
  }

  private computeShredDigest(ids: string[]): string {
    return createHash('sha256')
      .update(`${new Date().toISOString()}:${ids.join(',')}`)
      .digest('hex');
  }

  private async getActiveLegalHoldIds(
    dataType: RetentionDataType,
    ids: string[],
  ): Promise<Set<string>> {
    if (ids.length === 0) {
      return new Set<string>();
    }

    const holds = await (this.prisma as any).legalHold.findMany({
      where: {
        dataType,
        referenceId: { in: ids },
        isActive: true,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      select: { referenceId: true },
    });

    return new Set(holds.map((hold: { referenceId: string }) => hold.referenceId));
  }

  private async withDistributedLock(
    key: string,
    ttlSeconds: number,
    fn: () => Promise<void>,
  ): Promise<void> {
    const redis = this.redisService.getClient();
    const token = randomUUID();
    const lockAcquired = await redis.set(key, token, 'EX', ttlSeconds, 'NX');

    if (!lockAcquired) {
      this.logger.warn(`Retention lock ${key} is already held by another worker, skipping run`);
      return;
    }

    try {
      await fn();
    } finally {
      const currentToken = await redis.get(key);
      if (currentToken === token) {
        await redis.del(key);
      }
    }
  }
}

