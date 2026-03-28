// src/data-residency/data-residency.service.ts
import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface DataResidencyRule {
  id: string;
  name: string;
  regions: string[]; // Allowed regions for this rule
  dataTypes: string[]; // Types of data this rule applies to
  complianceLevel: 'strict' | 'flexible' | 'permissive';
  encryptionRequired: boolean;
  retentionPeriod?: number; // days
  auditRequired: boolean;
}

export interface DataClassification {
  type: string;
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  residencyRules: string[]; // Rule IDs that apply
  encryptionLevel: 'none' | 'standard' | 'high' | 'military';
}

export interface ResidencyRequest {
  userId: string;
  userRegion: string;
  dataType: string;
  operation: 'read' | 'write' | 'delete';
  dataSize?: number;
  sourceRegion?: string;
  destinationRegion?: string;
}

@Injectable()
export class DataResidencyService {
  private readonly logger = new Logger(DataResidencyService.name);
  private rules: DataResidencyRule[] = [];
  private classifications: DataClassification[] = [];

  constructor(private configService: ConfigService) {
    this.initializeRules();
    this.initializeClassifications();
  }

  private initializeRules() {
    // GDPR compliance for EU data
    this.rules.push({
      id: 'gdpr-eu',
      name: 'GDPR EU Data Residency',
      regions: ['eu-west-1', 'eu-central-1', 'uksouth', 'westeurope'],
      dataTypes: ['user-data', 'personal-data', 'health-data'],
      complianceLevel: 'strict',
      encryptionRequired: true,
      retentionPeriod: 2555, // 7 years
      auditRequired: true,
    });

    // CCPA compliance for California data
    this.rules.push({
      id: 'ccpa-us-west',
      name: 'CCPA California Data Residency',
      regions: ['us-west-1', 'us-west-2'],
      dataTypes: ['user-data', 'personal-data'],
      complianceLevel: 'strict',
      encryptionRequired: true,
      retentionPeriod: 1825, // 5 years
      auditRequired: true,
    });

    // Financial data residency (SOX compliance)
    this.rules.push({
      id: 'sox-financial',
      name: 'SOX Financial Data Residency',
      regions: ['us-east-1', 'us-west-2', 'uksouth'],
      dataTypes: ['financial-data', 'transaction-data'],
      complianceLevel: 'strict',
      encryptionRequired: true,
      retentionPeriod: 2555, // 7 years
      auditRequired: true,
    });

    // General data residency for non-sensitive data
    this.rules.push({
      id: 'general-global',
      name: 'General Global Data Residency',
      regions: ['us-east-1', 'us-west-2', 'uksouth', 'westeurope', 'us-central1', 'europe-west1'],
      dataTypes: ['public-data', 'analytics-data', 'log-data'],
      complianceLevel: 'permissive',
      encryptionRequired: false,
      retentionPeriod: 365, // 1 year
      auditRequired: false,
    });
  }

  private initializeClassifications() {
    this.classifications = [
      {
        type: 'user-data',
        sensitivity: 'confidential',
        residencyRules: ['gdpr-eu', 'ccpa-us-west'],
        encryptionLevel: 'high',
      },
      {
        type: 'financial-data',
        sensitivity: 'restricted',
        residencyRules: ['sox-financial'],
        encryptionLevel: 'military',
      },
      {
        type: 'health-data',
        sensitivity: 'restricted',
        residencyRules: ['gdpr-eu'],
        encryptionLevel: 'military',
      },
      {
        type: 'analytics-data',
        sensitivity: 'internal',
        residencyRules: ['general-global'],
        encryptionLevel: 'standard',
      },
      {
        type: 'log-data',
        sensitivity: 'internal',
        residencyRules: ['general-global'],
        encryptionLevel: 'none',
      },
    ];
  }

  async validateDataAccess(request: ResidencyRequest): Promise<boolean> {
    const classification = this.classifications.find(c => c.type === request.dataType);

    if (!classification) {
      throw new BadRequestException(`Unknown data type: ${request.dataType}`);
    }

    // Check if operation is allowed based on user region and data residency rules
    const applicableRules = this.rules.filter(rule =>
      classification.residencyRules.includes(rule.id)
    );

    for (const rule of applicableRules) {
      const isRegionAllowed = rule.regions.includes(request.userRegion);

      if (rule.complianceLevel === 'strict' && !isRegionAllowed) {
        this.logger.warn(
          `Data residency violation: ${request.userId} from ${request.userRegion} ` +
          `attempted ${request.operation} on ${request.dataType} (rule: ${rule.name})`
        );

        // Log audit event
        await this.logAuditEvent({
          ...request,
          ruleId: rule.id,
          allowed: false,
          reason: `Region ${request.userRegion} not allowed for ${rule.name}`,
        });

        return false;
      }

      if (rule.complianceLevel === 'flexible' && !isRegionAllowed) {
        // For flexible rules, check if data can be routed to allowed region
        if (request.operation === 'write' && request.destinationRegion) {
          if (!rule.regions.includes(request.destinationRegion)) {
            return false;
          }
        }
      }
    }

    // Log successful access
    await this.logAuditEvent({
      ...request,
      allowed: true,
    });

    return true;
  }

  async getDataRouting(request: ResidencyRequest): Promise<string[]> {
    const classification = this.classifications.find(c => c.type === request.dataType);

    if (!classification) {
      throw new BadRequestException(`Unknown data type: ${request.dataType}`);
    }

    // Return allowed regions for this data type
    const allowedRegions: string[] = [];

    for (const ruleId of classification.residencyRules) {
      const rule = this.rules.find(r => r.id === ruleId);
      if (rule) {
        allowedRegions.push(...rule.regions);
      }
    }

    // Remove duplicates
    return [...new Set(allowedRegions)];
  }

  async enforceDataRetention(dataType: string): Promise<number | null> {
    const classification = this.classifications.find(c => c.type === dataType);

    if (!classification) {
      return null;
    }

    // Find the strictest retention period
    let maxRetention: number | null = null;

    for (const ruleId of classification.residencyRules) {
      const rule = this.rules.find(r => r.id === ruleId);
      if (rule && rule.retentionPeriod) {
        if (maxRetention === null || rule.retentionPeriod > maxRetention) {
          maxRetention = rule.retentionPeriod;
        }
      }
    }

    return maxRetention;
  }

  async getEncryptionRequirements(dataType: string): Promise<{
    required: boolean;
    level: string;
    algorithm?: string;
  }> {
    const classification = this.classifications.find(c => c.type === dataType);

    if (!classification) {
      return { required: false, level: 'none' };
    }

    // Check if any rule requires encryption
    const encryptionRequired = classification.residencyRules.some(ruleId => {
      const rule = this.rules.find(r => r.id === ruleId);
      return rule?.encryptionRequired;
    });

    return {
      required: encryptionRequired,
      level: classification.encryptionLevel,
      algorithm: classification.encryptionLevel === 'military' ? 'AES-256-GCM' :
                classification.encryptionLevel === 'high' ? 'AES-256-CBC' :
                classification.encryptionLevel === 'standard' ? 'AES-128-CBC' : undefined,
    };
  }

  private async logAuditEvent(event: any): Promise<void> {
    // TODO: Implement audit logging to database
    this.logger.log(`Data residency audit: ${JSON.stringify(event)}`);
  }

  // Public API methods
  getAllRules(): DataResidencyRule[] {
    return [...this.rules];
  }

  getAllClassifications(): DataClassification[] {
    return [...this.classifications];
  }

  async addRule(rule: DataResidencyRule): Promise<void> {
    // Validate rule
    if (this.rules.find(r => r.id === rule.id)) {
      throw new BadRequestException(`Rule with ID ${rule.id} already exists`);
    }

    this.rules.push(rule);
    this.logger.log(`Added data residency rule: ${rule.name}`);
  }

  async updateClassification(classification: DataClassification): Promise<void> {
    const index = this.classifications.findIndex(c => c.type === classification.type);

    if (index === -1) {
      this.classifications.push(classification);
    } else {
      this.classifications[index] = classification;
    }

    this.logger.log(`Updated data classification: ${classification.type}`);
  }
}