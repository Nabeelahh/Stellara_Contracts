// src/secrets-management/secret-access-logger.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

export interface AccessLogEntry {
  secretName: string;
  accessedBy: string;
  accessType: 'read' | 'write' | 'rotate' | 'revoke';
  accessMethod: 'api' | 'sdk' | 'console' | 'cache';
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
  errorMessage?: string;
}

@Injectable()
export class SecretAccessLoggerService {
  private readonly logger = new Logger(SecretAccessLoggerService.name);
  private accessPatterns = new Map<string, { count: number; lastAccess: Date; alertsTriggered: number }>();

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {}

  /**
   * Log access to a secret
   */
  async logAccess(
    secretName: string,
    accessedBy: string,
    accessType: 'read' | 'write' | 'rotate' | 'revoke',
    accessMethod: 'api' | 'sdk' | 'console' | 'cache',
    success: boolean,
    errorMessage?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    try {
      // Get secret ID
      const secret = await this.prisma.secret.findUnique({
        where: { secretName },
      });

      if (!secret) {
        this.logger.warn(`Attempted to log access for unknown secret: ${secretName}`);
        return;
      }

      // Create access log entry
      await this.prisma.secretAccessLog.create({
        data: {
          secretId: secret.id,
          accessedBy,
          accessType,
          accessMethod,
          ipAddress,
          userAgent,
          success,
          errorMessage,
        },
      });

      // Check for unusual access patterns
      await this.detectUnusualAccess(secretName, accessedBy, accessType, accessMethod, success);

      // Log to application logger
      const logLevel = success ? 'debug' : 'warn';
      this.logger[logLevel](
        `Secret access: ${secretName} by ${accessedBy} (${accessType}) - ${success ? 'SUCCESS' : 'FAILED'}`,
      );
    } catch (error) {
      this.logger.error(`Failed to log secret access: ${error.message}`);
    }
  }

  /**
   * Detect unusual access patterns and create alerts
   */
  private async detectUnusualAccess(
    secretName: string,
    accessedBy: string,
    accessType: string,
    accessMethod: string,
    success: boolean,
  ): Promise<void> {
    const patternKey = `${secretName}:${accessedBy}:${accessType}`;
    const now = new Date();

    // Get or create access pattern
    let pattern = this.accessPatterns.get(patternKey);
    if (!pattern) {
      pattern = { count: 0, lastAccess: now, alertsTriggered: 0 };
      this.accessPatterns.set(patternKey, pattern);
    }

    pattern.count++;
    pattern.lastAccess = now;

    // Check for unusual patterns
    const alerts = [];

    // 1. High frequency access (more than 10 accesses per minute)
    if (pattern.count > 10) {
      alerts.push({
        type: 'high_frequency_access',
        severity: 'high',
        message: `Unusual high frequency access to secret ${secretName} by ${accessedBy}`,
        details: { accessCount: pattern.count, timeWindow: '1_minute' },
      });
      pattern.alertsTriggered++;
    }

    // 2. Failed access attempts (more than 5 failures in a row)
    if (!success) {
      const recentFailures = await this.getRecentFailures(secretName, accessedBy, 5);
      if (recentFailures >= 5) {
        alerts.push({
          type: 'repeated_access_failures',
          severity: 'medium',
          message: `Repeated failed access attempts to secret ${secretName} by ${accessedBy}`,
          details: { failureCount: recentFailures },
        });
      }
    }

    // 3. Access from unusual method or source
    if (accessMethod === 'console' && accessType !== 'read') {
      alerts.push({
        type: 'unusual_access_method',
        severity: 'low',
        message: `Unusual access method (${accessMethod}) for ${accessType} operation on ${secretName}`,
        details: { accessMethod, accessType },
      });
    }

    // 4. Access to sensitive secrets
    const sensitiveSecrets = ['jwt', 'database', 'stripe'];
    const secret = await this.prisma.secret.findUnique({ where: { secretName } });
    if (secret && sensitiveSecrets.includes(secret.secretType) && accessType === 'read') {
      // Log but don't alert for normal access to sensitive secrets
      this.logger.info(`Access to sensitive ${secret.secretType} secret: ${secretName}`);
    }

    // Create alerts
    for (const alert of alerts) {
      await this.createAlert(secretName, alert.type, alert.severity, alert.message, alert.details);
    }

    // Clean up old patterns (older than 1 hour)
    for (const [key, pattern] of this.accessPatterns.entries()) {
      if (now.getTime() - pattern.lastAccess.getTime() > 60 * 60 * 1000) {
        this.accessPatterns.delete(key);
      }
    }
  }

  /**
   * Get recent failure count for a secret and accessor
   */
  private async getRecentFailures(secretName: string, accessedBy: string, limit: number): Promise<number> {
    const secret = await this.prisma.secret.findUnique({ where: { secretName } });
    if (!secret) return 0;

    const recentLogs = await this.prisma.secretAccessLog.findMany({
      where: {
        secretId: secret.id,
        accessedBy,
        success: false,
        accessedAt: {
          gte: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
        },
      },
      orderBy: { accessedAt: 'desc' },
      take: limit,
    });

    return recentLogs.length;
  }

  /**
   * Create an alert for unusual activity
   */
  private async createAlert(
    secretName: string,
    alertType: string,
    severity: string,
    message: string,
    details?: any,
  ): Promise<void> {
    try {
      const secret = await this.prisma.secret.findUnique({ where: { secretName } });

      await this.prisma.secretAlert.create({
        data: {
          secretId: secret?.id,
          alertType,
          severity,
          message,
          details,
        },
      });

      this.logger.warn(`Security Alert: ${message}`, { secretName, alertType, severity, details });

      // In production, this would also send notifications to security team
      // await this.sendSecurityNotification(alertType, severity, message, details);
    } catch (error) {
      this.logger.error(`Failed to create security alert: ${error.message}`);
    }
  }

  /**
   * Get access logs for a secret
   */
  async getAccessLogs(
    secretName: string,
    limit: number = 100,
    offset: number = 0,
  ): Promise<any[]> {
    const secret = await this.prisma.secret.findUnique({ where: { secretName } });
    if (!secret) return [];

    return this.prisma.secretAccessLog.findMany({
      where: { secretId: secret.id },
      orderBy: { accessedAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  /**
   * Get security alerts
   */
  async getSecurityAlerts(
    resolved: boolean = false,
    limit: number = 50,
  ): Promise<any[]> {
    return this.prisma.secretAlert.findMany({
      where: { resolved },
      include: {
        secret: {
          select: {
            secretName: true,
            secretType: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  /**
   * Resolve a security alert
   */
  async resolveAlert(alertId: string, resolvedBy: string): Promise<boolean> {
    try {
      await this.prisma.secretAlert.update({
        where: { id: alertId },
        data: {
          resolved: true,
          resolvedAt: new Date(),
          resolvedBy,
        },
      });
      return true;
    } catch (error) {
      this.logger.error(`Failed to resolve alert ${alertId}: ${error.message}`);
      return false;
    }
  }

  /**
   * Get access statistics
   */
  async getAccessStatistics(timeRangeHours: number = 24): Promise<any> {
    const since = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);

    const [
      totalAccesses,
      successfulAccesses,
      failedAccesses,
      accessByType,
      accessBySecret,
    ] = await Promise.all([
      this.prisma.secretAccessLog.count({
        where: { accessedAt: { gte: since } },
      }),
      this.prisma.secretAccessLog.count({
        where: { accessedAt: { gte: since }, success: true },
      }),
      this.prisma.secretAccessLog.count({
        where: { accessedAt: { gte: since }, success: false },
      }),
      this.prisma.secretAccessLog.groupBy({
        by: ['accessType'],
        where: { accessedAt: { gte: since } },
        _count: { id: true },
      }),
      this.prisma.secretAccessLog.groupBy({
        by: ['secretId'],
        where: { accessedAt: { gte: since } },
        _count: { id: true },
      }),
    ]);

    return {
      timeRange: `${timeRangeHours} hours`,
      totalAccesses,
      successfulAccesses,
      failedAccesses,
      successRate: totalAccesses > 0 ? (successfulAccesses / totalAccesses) * 100 : 0,
      accessByType: accessByType.map(item => ({
        type: item.accessType,
        count: item._count.id,
      })),
      topSecretsAccessed: await Promise.all(
        accessBySecret
          .sort((a, b) => b._count.id - a._count.id)
          .slice(0, 10)
          .map(async (item) => {
            const secret = await this.prisma.secret.findUnique({
              where: { id: item.secretId },
              select: { secretName: true, secretType: true },
            });
            return {
              secretName: secret?.secretName || 'Unknown',
              secretType: secret?.secretType || 'Unknown',
              accessCount: item._count.id,
            };
          }),
      ),
    };
  }

  /**
   * Send security notification (placeholder for actual implementation)
   */
  private async sendSecurityNotification(
    alertType: string,
    severity: string,
    message: string,
    details?: any,
  ): Promise<void> {
    // In production, this would send notifications to:
    // - Security team email/Slack
    // - SIEM system
    // - Incident response system

    this.logger.warn(`Security notification would be sent: ${alertType} (${severity}) - ${message}`, details);

    // Example implementation:
    // await this.notificationService.sendSecurityAlert({
    //   type: alertType,
    //   severity,
    //   message,
    //   details,
    //   recipients: ['security@company.com'],
    // });
  }
}