import * as crypto from 'crypto';

import { AuditAction, Prisma } from '@prisma/client';
import {
  AuditContext,
  AuditLogEntry,
  AuditQueryOptions,
  AuditQueryResult,
  DataChangeRecord,
} from './interfaces/audit.interface';
import { Injectable, Logger } from '@nestjs/common';

import { AsyncContextService } from '../logging/services/async-context.service';
import { PrismaService } from '../prisma.service';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);
  private readonly sensitiveFields = [
    'password',
    'token',
    'secret',
    'apiKey',
    'refreshToken',
    'accessToken',
    'ssn',
    'creditCard',
    'cvv',
  ];

  constructor(
    private readonly prisma: PrismaService,
    private readonly asyncContext: AsyncContextService,
  ) {}

  /**
   * Create an audit log entry
   */
  async log(entry: AuditLogEntry): Promise<void> {
    try {
      const sanitizedEntry = this.sanitizeEntry(entry);
      const checksum = this.generateChecksum(sanitizedEntry);

      await this.prisma.auditLog.create({
        data: {
          correlationId: sanitizedEntry.correlationId,
          tenantId: sanitizedEntry.tenantId,
          userId: sanitizedEntry.userId,
          action: sanitizedEntry.action,
          entityType: sanitizedEntry.entityType,
          entityId: sanitizedEntry.entityId,
          method: sanitizedEntry.method,
          path: sanitizedEntry.path,
          statusCode: sanitizedEntry.statusCode,
          ipAddress: sanitizedEntry.ipAddress,
          userAgent: sanitizedEntry.userAgent,
          requestBody: sanitizedEntry.requestBody as Prisma.InputJsonValue,
          responseBody: sanitizedEntry.responseBody as Prisma.InputJsonValue,
          previousState: sanitizedEntry.previousState as Prisma.InputJsonValue,
          newState: sanitizedEntry.newState as Prisma.InputJsonValue,
          changedFields: sanitizedEntry.changedFields || [],
          metadata: sanitizedEntry.metadata as Prisma.InputJsonValue,
          duration: sanitizedEntry.duration,
          errorMessage: sanitizedEntry.errorMessage,
          checksum,
        },
      });
    } catch (error) {
      // Log error but don't throw to prevent audit failures from affecting main operations
      this.logger.error(`Failed to create audit log: ${error.message}`, error.stack);
    }
  }

  /**
   * Log a data change (create, update, delete)
   */
  async logDataChange(
    action: AuditAction,
    change: DataChangeRecord,
    context?: AuditContext,
  ): Promise<void> {
    const auditContext = context || this.getContextFromAsync();

    await this.log({
      ...auditContext,
      action,
      entityType: change.entityType,
      entityId: change.entityId,
      previousState: change.previousState,
      newState: change.newState,
      changedFields: change.changedFields,
    });
  }

  /**
   * Log a system event
   */
  async logSystemEvent(eventType: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.log({
      action: AuditAction.SYSTEM_EVENT,
      entityType: eventType,
      metadata,
      correlationId: this.asyncContext.getCorrelationId(),
    });
  }

  /**
   * Log an error event
   */
  async logError(
    entityType: string,
    errorMessage: string,
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    const context = this.getContextFromAsync();

    await this.log({
      ...context,
      action: AuditAction.ERROR,
      entityType,
      errorMessage,
      metadata,
    });
  }

  /**
   * Log access denied event
   */
  async logAccessDenied(entityType: string, entityId?: string, reason?: string): Promise<void> {
    const context = this.getContextFromAsync();

    await this.log({
      ...context,
      action: AuditAction.ACCESS_DENIED,
      entityType,
      entityId,
      errorMessage: reason,
    });
  }

  /**
   * Query audit logs with filters and pagination
   */
  async query(options: AuditQueryOptions): Promise<AuditQueryResult> {
    const {
      tenantId,
      userId,
      entityType,
      entityId,
      action,
      correlationId,
      startDate,
      endDate,
      statusCode,
      page = 1,
      limit = 50,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = options;

    const where: Prisma.AuditLogWhereInput = {};

    if (tenantId) where.tenantId = tenantId;
    if (userId) where.userId = userId;
    if (entityType) where.entityType = entityType;
    if (entityId) where.entityId = entityId;
    if (action) where.action = action;
    if (correlationId) where.correlationId = correlationId;
    if (statusCode) where.statusCode = statusCode;

    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = startDate;
      if (endDate) where.createdAt.lte = endDate;
    }

    const [data, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { [sortBy]: sortOrder },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return {
      data: data.map((log) => this.mapToAuditLogEntry(log)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Get a single audit log entry by ID
   */
  async getById(id: string): Promise<AuditLogEntry | null> {
    const log = await this.prisma.auditLog.findUnique({ where: { id } });
    return log ? this.mapToAuditLogEntry(log) : null;
  }

  /**
   * Get audit logs for a specific entity
   */
  async getEntityHistory(
    entityType: string,
    entityId: string,
    options?: { limit?: number; page?: number },
  ): Promise<AuditQueryResult> {
    return this.query({
      entityType,
      entityId,
      ...options,
    });
  }

  /**
   * Get user activity logs
   */
  async getUserActivity(userId: string, options?: AuditQueryOptions): Promise<AuditQueryResult> {
    return this.query({
      ...options,
      userId,
    });
  }

  /**
   * Verify the integrity of an audit log entry
   */
  async verifyIntegrity(id: string): Promise<boolean> {
    const log = await this.prisma.auditLog.findUnique({ where: { id } });
    if (!log) return false;

    const entry = this.mapToAuditLogEntry(log);
    const computedChecksum = this.generateChecksum(entry);

    return log.checksum === computedChecksum;
  }

  /**
   * Get audit statistics for a time period
   */
  async getStatistics(
    startDate: Date,
    endDate: Date,
    tenantId?: string,
  ): Promise<{
    totalLogs: number;
    byAction: Record<string, number>;
    byEntityType: Record<string, number>;
    errorCount: number;
    accessDeniedCount: number;
  }> {
    const where: Prisma.AuditLogWhereInput = {
      createdAt: { gte: startDate, lte: endDate },
    };
    if (tenantId) where.tenantId = tenantId;

    const [totalLogs, byAction, byEntityType, errorCount, accessDeniedCount] = await Promise.all([
      this.prisma.auditLog.count({ where }),
      this.prisma.auditLog.groupBy({
        by: ['action'],
        where,
        _count: true,
      }),
      this.prisma.auditLog.groupBy({
        by: ['entityType'],
        where,
        _count: true,
      }),
      this.prisma.auditLog.count({
        where: { ...where, action: AuditAction.ERROR },
      }),
      this.prisma.auditLog.count({
        where: { ...where, action: AuditAction.ACCESS_DENIED },
      }),
    ]);

    return {
      totalLogs,
      byAction: byAction.reduce((acc, item) => ({ ...acc, [item.action]: item._count }), {}),
      byEntityType: byEntityType.reduce(
        (acc, item) => ({ ...acc, [item.entityType]: item._count }),
        {},
      ),
      errorCount,
      accessDeniedCount,
    };
  }

  /**
   * Calculate field differences between two states
   */
  calculateChangedFields(
    previousState: Record<string, unknown> | undefined,
    newState: Record<string, unknown> | undefined,
  ): string[] {
    if (!previousState && !newState) return [];
    if (!previousState) return Object.keys(newState || {});
    if (!newState) return Object.keys(previousState);

    const changedFields: string[] = [];
    const allKeys = new Set([...Object.keys(previousState), ...Object.keys(newState)]);

    for (const key of allKeys) {
      if (JSON.stringify(previousState[key]) !== JSON.stringify(newState[key])) {
        changedFields.push(key);
      }
    }

    return changedFields;
  }

  /**
   * Get current audit context from async context
   */
  private getContextFromAsync(): AuditContext {
    return {
      correlationId: this.asyncContext.getCorrelationId(),
      userId: this.asyncContext.getUserId(),
      tenantId: this.asyncContext.getTenantId(),
    };
  }

  /**
   * Sanitize sensitive data from audit entry
   */
  private sanitizeEntry(entry: AuditLogEntry): AuditLogEntry {
    return {
      ...entry,
      requestBody: this.sanitizeObject(entry.requestBody),
      responseBody: this.sanitizeObject(entry.responseBody),
      previousState: this.sanitizeObject(entry.previousState),
      newState: this.sanitizeObject(entry.newState),
    };
  }

  /**
   * Recursively sanitize sensitive fields from an object
   */
  private sanitizeObject(
    obj: Record<string, unknown> | undefined,
  ): Record<string, unknown> | undefined {
    if (!obj) return obj;

    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      const isSensitive = this.sensitiveFields.some((field) =>
        lowerKey.includes(field.toLowerCase()),
      );

      if (isSensitive) {
        sanitized[key] = '[REDACTED]';
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        sanitized[key] = this.sanitizeObject(value as Record<string, unknown>);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map((item) =>
          typeof item === 'object' && item !== null
            ? this.sanitizeObject(item as Record<string, unknown>)
            : item,
        );
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Generate a SHA-256 checksum for tamper detection
   */
  private generateChecksum(entry: AuditLogEntry): string {
    const dataToHash = JSON.stringify({
      correlationId: entry.correlationId,
      tenantId: entry.tenantId,
      userId: entry.userId,
      action: entry.action,
      entityType: entry.entityType,
      entityId: entry.entityId,
      method: entry.method,
      path: entry.path,
      statusCode: entry.statusCode,
      requestBody: entry.requestBody,
      responseBody: entry.responseBody,
      previousState: entry.previousState,
      newState: entry.newState,
      changedFields: entry.changedFields,
      errorMessage: entry.errorMessage,
    });

    return crypto.createHash('sha256').update(dataToHash).digest('hex');
  }

  /**
   * Map Prisma model to AuditLogEntry interface
   */
  private mapToAuditLogEntry(log: any): AuditLogEntry {
    return {
      correlationId: log.correlationId,
      tenantId: log.tenantId,
      userId: log.userId,
      action: log.action,
      entityType: log.entityType,
      entityId: log.entityId,
      method: log.method,
      path: log.path,
      statusCode: log.statusCode,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      requestBody: log.requestBody as Record<string, unknown>,
      responseBody: log.responseBody as Record<string, unknown>,
      previousState: log.previousState as Record<string, unknown>,
      newState: log.newState as Record<string, unknown>,
      changedFields: log.changedFields,
      metadata: log.metadata as Record<string, unknown>,
      duration: log.duration,
      errorMessage: log.errorMessage,
    };
  }
}
