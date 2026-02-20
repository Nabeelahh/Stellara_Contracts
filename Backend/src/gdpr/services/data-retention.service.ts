import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from '../../audit/audit.entity';
import { AuditService } from '../../audit/audit.service';
import { Consent } from '../entities/consent.entity';

export interface RetentionPolicy {
  entity: string;
  retentionDays: number;
  action: 'delete' | 'archive' | 'anonymize';
}

export interface CleanupResult {
  entity: string;
  processed: number;
  deleted: number;
  archived: number;
  anonymized: number;
}

@Injectable()
export class DataRetentionService {
  private readonly logger = new Logger(DataRetentionService.name);

  // Default retention policies
  private readonly RETENTION_POLICIES: RetentionPolicy[] = [
    { entity: 'audit_logs', retentionDays: 730, action: 'delete' }, // 2 years
    { entity: 'consents', retentionDays: 1825, action: 'archive' }, // 5 years
    { entity: 'users_inactive', retentionDays: 30, action: 'delete' }, // 30 days
    { entity: 'system_logs', retentionDays: 90, action: 'delete' }, // 90 days
  ];

  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
    @InjectRepository(Consent)
    private readonly consentRepository: Repository<Consent>,
    private readonly auditService: AuditService,
  ) {}

  async executeRetentionCleanup(): Promise<CleanupResult[]> {
    const results: CleanupResult[] = [];

    for (const policy of this.RETENTION_POLICIES) {
      try {
        const result = await this.processRetentionPolicy(policy);
        results.push(result);
        this.logger.log(`Retention policy executed for ${policy.entity}: ${JSON.stringify(result)}`);
      } catch (error) {
        this.logger.error(`Failed to execute retention policy for ${policy.entity}:`, error);
        results.push({
          entity: policy.entity,
          processed: 0,
          deleted: 0,
          archived: 0,
          anonymized: 0,
        });
      }
    }

    await this.auditService.logAction('RETENTION_CLEANUP_COMPLETED', 'system', 'batch', {
      policies: this.RETENTION_POLICIES.length,
      results,
    });

    return results;
  }

  async getRetentionPolicies(): Promise<RetentionPolicy[]> {
    return [...this.RETENTION_POLICIES];
  }

  async updateRetentionPolicy(entity: string, newPolicy: Partial<RetentionPolicy>): Promise<void> {
    const policyIndex = this.RETENTION_POLICIES.findIndex(p => p.entity === entity);
    
    if (policyIndex === -1) {
      throw new Error(`Retention policy for entity ${entity} not found`);
    }

    this.RETENTION_POLICIES[policyIndex] = {
      ...this.RETENTION_POLICIES[policyIndex],
      ...newPolicy,
    };

    await this.auditService.logAction('RETENTION_POLICY_UPDATED', 'system', entity, {
      oldPolicy: this.RETENTION_POLICIES[policyIndex],
      newPolicy,
    });
  }

  private async processRetentionPolicy(policy: RetentionPolicy): Promise<CleanupResult> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - policy.retentionDays);

    let result: CleanupResult = {
      entity: policy.entity,
      processed: 0,
      deleted: 0,
      archived: 0,
      anonymized: 0,
    };

    switch (policy.entity) {
      case 'audit_logs':
        result = await this.cleanupAuditLogs(cutoffDate, policy.action);
        break;
      case 'consents':
        result = await this.cleanupConsents(cutoffDate, policy.action);
        break;
      case 'users_inactive':
        result = await this.cleanupInactiveUsers(cutoffDate, policy.action);
        break;
      case 'system_logs':
        result = await this.cleanupSystemLogs(cutoffDate, policy.action);
        break;
      default:
        this.logger.warn(`Unknown retention entity: ${policy.entity}`);
    }

    return result;
  }

  private async cleanupAuditLogs(cutoffDate: Date, action: string): Promise<CleanupResult> {
    const oldLogs = await this.auditLogRepository.find({
      where: {
        timestamp: new Date(cutoffDate.getTime() - 24 * 60 * 60 * 1000),
      },
    });

    let deleted = 0;
    let archived = 0;
    let anonymized = 0;

    if (action === 'delete') {
      const deleteResult = await this.auditLogRepository.delete({
        timestamp: new Date(cutoffDate.getTime() - 24 * 60 * 60 * 1000),
      });
      deleted = deleteResult.affected || 0;
    } else if (action === 'anonymize') {
      // Anonymize old audit logs (remove sensitive metadata)
      for (const log of oldLogs) {
        if (log.metadata) {
          // Remove potentially sensitive metadata
          delete log.metadata.ip_address;
          delete log.metadata.user_agent;
          delete log.metadata.email;
          log.metadata = { ...log.metadata, anonymized: true };
          await this.auditLogRepository.save(log);
        }
      }
      anonymized = oldLogs.length;
    }
    // Archive action would typically move data to cold storage - not implemented here

    return {
      entity: 'audit_logs',
      processed: oldLogs.length,
      deleted,
      archived,
      anonymized,
    };
  }

  private async cleanupConsents(cutoffDate: Date, action: string): Promise<CleanupResult> {
    const oldConsents = await this.consentRepository.find({
      where: {
        grantedAt: new Date(cutoffDate.getTime() - 24 * 60 * 60 * 1000),
      },
    });

    let deleted = 0;
    let archived = 0;

    if (action === 'delete') {
      const deleteResult = await this.consentRepository.delete({
        grantedAt: new Date(cutoffDate.getTime() - 24 * 60 * 60 * 1000),
      });
      deleted = deleteResult.affected || 0;
    } else if (action === 'archive') {
      // Mark consents as archived (would move to archive table in production)
      for (const consent of oldConsents) {
        consent.status = 'archived' as any; // Type assertion for archived status
        await this.consentRepository.save(consent);
      }
      archived = oldConsents.length;
    }

    return {
      entity: 'consents',
      processed: oldConsents.length,
      deleted,
      archived,
      anonymized: 0,
    };
  }

  private async cleanupInactiveUsers(cutoffDate: Date, action: string): Promise<CleanupResult> {
    // This would require access to User repository
    // For now, return placeholder result
    return {
      entity: 'users_inactive',
      processed: 0,
      deleted: 0,
      archived: 0,
      anonymized: 0,
    };
  }

  private async cleanupSystemLogs(cutoffDate: Date, action: string): Promise<CleanupResult> {
    // System logs cleanup would depend on logging implementation
    // This is a placeholder implementation
    return {
      entity: 'system_logs',
      processed: 0,
      deleted: 0,
      archived: 0,
      anonymized: 0,
    };
  }

  async getRetentionStatistics(): Promise<Record<string, {
    total: number;
    withinRetention: number;
    expired: number;
  }>> {
    const now = new Date();
    const stats: Record<string, {
      total: number;
      withinRetention: number;
      expired: number;
    }> = {};

    // Audit logs statistics
    const auditLogs = await this.auditLogRepository.find();
    const auditWithinRetention = auditLogs.filter(log => 
      new Date(log.timestamp) > new Date(now.getTime() - (730 * 24 * 60 * 60 * 1000))
    );
    
    stats['audit_logs'] = {
      total: auditLogs.length,
      withinRetention: auditWithinRetention.length,
      expired: auditLogs.length - auditWithinRetention.length,
    };

    // Consents statistics
    const consents = await this.consentRepository.find();
    const consentWithinRetention = consents.filter(consent => 
      new Date(consent.grantedAt) > new Date(now.getTime() - (1825 * 24 * 60 * 60 * 1000))
    );
    
    stats['consents'] = {
      total: consents.length,
      withinRetention: consentWithinRetention.length,
      expired: consents.length - consentWithinRetention.length,
    };

    return stats;
  }

  async scheduleRetentionCleanup(): Promise<void> {
    // This would typically be called by a scheduled job
    // For now, just execute immediately
    await this.executeRetentionCleanup();
  }
}