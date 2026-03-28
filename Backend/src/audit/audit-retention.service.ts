import { AuditAction, Prisma } from '@prisma/client';
import { Cron, CronExpression } from '@nestjs/schedule';
import { Injectable, Logger } from '@nestjs/common';
import { RetentionExecutionResult, RetentionPolicyConfig } from './interfaces/audit.interface';

import { AuditService } from './audit.service';
import { PrismaService } from '../prisma.service';

@Injectable()
export class AuditRetentionService {
  private readonly logger = new Logger(AuditRetentionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Create a new retention policy
   */
  async createPolicy(config: RetentionPolicyConfig): Promise<string> {
    const policy = await this.prisma.auditRetentionPolicy.create({
      data: {
        name: config.name,
        tenantId: config.tenantId,
        retentionDays: config.retentionDays,
        entityTypes: config.entityTypes || [],
        actions: config.actions?.map((a) => a.toString()) || [],
        archiveEnabled: config.archiveEnabled || false,
        archiveLocation: config.archiveLocation,
        isActive: true,
      },
    });

    await this.auditService.logSystemEvent('RETENTION_POLICY_CREATED', {
      policyId: policy.id,
      policyName: policy.name,
    });

    return policy.id;
  }

  /**
   * Update an existing retention policy
   */
  async updatePolicy(
    id: string,
    updates: Partial<RetentionPolicyConfig> & { isActive?: boolean },
  ): Promise<void> {
    const data: Prisma.AuditRetentionPolicyUpdateInput = {};

    if (updates.name !== undefined) data.name = updates.name;
    if (updates.retentionDays !== undefined) data.retentionDays = updates.retentionDays;
    if (updates.entityTypes !== undefined) data.entityTypes = updates.entityTypes;
    if (updates.actions !== undefined) data.actions = updates.actions.map((a) => a.toString());
    if (updates.archiveEnabled !== undefined) data.archiveEnabled = updates.archiveEnabled;
    if (updates.archiveLocation !== undefined) data.archiveLocation = updates.archiveLocation;
    if (updates.isActive !== undefined) data.isActive = updates.isActive;

    await this.prisma.auditRetentionPolicy.update({
      where: { id },
      data,
    });

    await this.auditService.logSystemEvent('RETENTION_POLICY_UPDATED', {
      policyId: id,
      updates,
    });
  }

  /**
   * Delete a retention policy
   */
  async deletePolicy(id: string): Promise<void> {
    const policy = await this.prisma.auditRetentionPolicy.delete({
      where: { id },
    });

    await this.auditService.logSystemEvent('RETENTION_POLICY_DELETED', {
      policyId: id,
      policyName: policy.name,
    });
  }

  /**
   * Get all retention policies
   */
  async getPolicies(tenantId?: string) {
    const where: Prisma.AuditRetentionPolicyWhereInput = {};
    if (tenantId) {
      where.OR = [{ tenantId }, { tenantId: null }];
    }

    return this.prisma.auditRetentionPolicy.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Get a single retention policy by ID
   */
  async getPolicy(id: string) {
    return this.prisma.auditRetentionPolicy.findUnique({
      where: { id },
    });
  }

  /**
   * Execute a specific retention policy
   */
  async executePolicy(policyId: string): Promise<RetentionExecutionResult> {
    const policy = await this.prisma.auditRetentionPolicy.findUnique({
      where: { id: policyId },
    });

    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    if (!policy.isActive) {
      throw new Error(`Policy is not active: ${policyId}`);
    }

    return this.executePolicyInternal(policy);
  }

  /**
   * Run retention policies on a schedule (daily at 2 AM)
   */
  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async runScheduledRetention(): Promise<void> {
    this.logger.log('Starting scheduled retention policy execution');

    const policies = await this.prisma.auditRetentionPolicy.findMany({
      where: { isActive: true },
    });

    const results: RetentionExecutionResult[] = [];

    for (const policy of policies) {
      try {
        const result = await this.executePolicyInternal(policy);
        results.push(result);
        this.logger.log(
          `Executed retention policy "${policy.name}": deleted ${result.deletedCount}, archived ${result.archivedCount}`,
        );
      } catch (error) {
        this.logger.error(
          `Failed to execute retention policy "${policy.name}": ${error.message}`,
          error.stack,
        );
        results.push({
          policyId: policy.id,
          policyName: policy.name,
          deletedCount: 0,
          archivedCount: 0,
          executedAt: new Date(),
          errors: [error.message],
        });
      }
    }

    await this.auditService.logSystemEvent('RETENTION_SCHEDULED_RUN_COMPLETED', {
      policiesExecuted: results.length,
      totalDeleted: results.reduce((sum, r) => sum + r.deletedCount, 0),
      totalArchived: results.reduce((sum, r) => sum + r.archivedCount, 0),
      errors: results.flatMap((r) => r.errors || []),
    });
  }

  /**
   * Internal method to execute a retention policy
   */
  private async executePolicyInternal(policy: any): Promise<RetentionExecutionResult> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - policy.retentionDays);

    // Build the where clause
    const where: Prisma.AuditLogWhereInput = {
      createdAt: { lt: cutoffDate },
    };

    // Apply tenant filter
    if (policy.tenantId) {
      where.tenantId = policy.tenantId;
    }

    // Apply entity type filter
    if (policy.entityTypes && policy.entityTypes.length > 0) {
      where.entityType = { in: policy.entityTypes };
    }

    // Apply action filter
    if (policy.actions && policy.actions.length > 0) {
      where.action = { in: policy.actions as AuditAction[] };
    }

    let archivedCount = 0;
    let deletedCount = 0;

    // Archive if enabled
    if (policy.archiveEnabled) {
      const logsToArchive = await this.prisma.auditLog.findMany({
        where,
        take: 10000, // Process in batches
      });

      if (logsToArchive.length > 0) {
        archivedCount = await this.archiveLogs(logsToArchive, policy.archiveLocation);
      }
    }

    // Delete old logs
    const result = await this.prisma.auditLog.deleteMany({ where });
    deletedCount = result.count;

    // Update last executed timestamp
    await this.prisma.auditRetentionPolicy.update({
      where: { id: policy.id },
      data: { lastExecutedAt: new Date() },
    });

    return {
      policyId: policy.id,
      policyName: policy.name,
      deletedCount,
      archivedCount,
      executedAt: new Date(),
    };
  }

  /**
   * Archive logs to external storage
   */
  private async archiveLogs(logs: any[], archiveLocation?: string | null): Promise<number> {
    // This is a placeholder for actual archiving logic
    // In production, this would write to S3, GCS, or another storage system

    if (!archiveLocation) {
      this.logger.warn('Archive enabled but no archive location specified');
      return 0;
    }

    try {
      // Example: Write to a file (in production, use cloud storage)
      const archiveData = JSON.stringify(logs, null, 2);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `audit-archive-${timestamp}.json`;

      this.logger.log(`Archiving ${logs.length} logs to ${archiveLocation}/${filename}`);

      // TODO: Implement actual archive storage (S3, GCS, etc.)
      // await this.storageService.upload(archiveLocation, filename, archiveData);

      return logs.length;
    } catch (error) {
      this.logger.error(`Failed to archive logs: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get retention statistics
   */
  async getRetentionStats(): Promise<{
    totalPolicies: number;
    activePolicies: number;
    lastExecutionResults: {
      policyName: string;
      lastExecutedAt: Date | null;
    }[];
    oldestLogDate: Date | null;
    totalLogs: number;
  }> {
    const [totalPolicies, activePolicies, policies, oldestLog, totalLogs] = await Promise.all([
      this.prisma.auditRetentionPolicy.count(),
      this.prisma.auditRetentionPolicy.count({ where: { isActive: true } }),
      this.prisma.auditRetentionPolicy.findMany({
        select: { name: true, lastExecutedAt: true },
        orderBy: { lastExecutedAt: 'desc' },
        take: 10,
      }),
      this.prisma.auditLog.findFirst({
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true },
      }),
      this.prisma.auditLog.count(),
    ]);

    return {
      totalPolicies,
      activePolicies,
      lastExecutionResults: policies.map((p) => ({
        policyName: p.name,
        lastExecutedAt: p.lastExecutedAt,
      })),
      oldestLogDate: oldestLog?.createdAt || null,
      totalLogs,
    };
  }

  /**
   * Manually trigger cleanup for a specific date range
   */
  async manualCleanup(
    beforeDate: Date,
    options?: {
      tenantId?: string;
      entityTypes?: string[];
      actions?: AuditAction[];
      dryRun?: boolean;
    },
  ): Promise<{ count: number; dryRun: boolean }> {
    const where: Prisma.AuditLogWhereInput = {
      createdAt: { lt: beforeDate },
    };

    if (options?.tenantId) where.tenantId = options.tenantId;
    if (options?.entityTypes?.length) where.entityType = { in: options.entityTypes };
    if (options?.actions?.length) where.action = { in: options.actions };

    if (options?.dryRun) {
      const count = await this.prisma.auditLog.count({ where });
      return { count, dryRun: true };
    }

    const result = await this.prisma.auditLog.deleteMany({ where });

    await this.auditService.logSystemEvent('MANUAL_CLEANUP_EXECUTED', {
      beforeDate: beforeDate.toISOString(),
      options,
      deletedCount: result.count,
    });

    return { count: result.count, dryRun: false };
  }
}
