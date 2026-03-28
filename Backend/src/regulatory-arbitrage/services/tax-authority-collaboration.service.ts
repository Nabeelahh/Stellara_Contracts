import { Injectable, Logger } from '@nestjs/common';
import {
  TaxAuthorityIntegration,
  ComplianceAlert,
  AlertType,
  RiskLevel,
  SyncStatus,
  AuthType,
  DataMapping
} from '../interfaces/regulatory-arbitrage.interface';

@Injectable()
export class TaxAuthorityCollaborationService {
  private readonly logger = new Logger(TaxAuthorityCollaborationService.name);
  private readonly integrations = new Map<string, TaxAuthorityIntegration>();
  private readonly reportingQueue = new Map<string, any[]>();
  private readonly syncHistory = new Map<string, any[]>();

  constructor() {
    this.initializeIntegrations();
  }

  async reportToTaxAuthority(
    authority: string,
    alerts: ComplianceAlert[],
    evidencePackage: any,
    priority: 'immediate' | 'daily' | 'weekly' | 'monthly' = 'daily'
  ): Promise<{
    success: boolean;
    reportId?: string;
    submittedAt?: Date;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Reporting ${alerts.length} alerts to tax authority: ${authority}`);

    try {
      const integration = this.integrations.get(authority);
      if (!integration) {
        return {
          success: false,
          error: `Tax authority integration not found: ${authority}`
        };
      }

      if (!integration.enabled) {
        return {
          success: false,
          error: `Tax authority integration disabled: ${authority}`
        };
      }

      // Prepare report data
      const reportData = await this.prepareReportData(
        authority,
        alerts,
        evidencePackage,
        integration
      );

      // Submit report
      const submission = await this.submitReport(integration, reportData);
      
      // Queue for follow-up
      if (!this.reportingQueue.has(authority)) {
        this.reportingQueue.set(authority, []);
      }
      this.reportingQueue.get(authority)!.push({
        reportId: submission.reportId,
        alerts: alerts.map(alert => alert.id),
        submittedAt: submission.submittedAt,
        status: 'submitted',
        priority
      });

      // Send confirmation
      await this.sendReportConfirmation(integration, submission);

      const endTime = Date.now();
      
      this.logger.log(`Report submitted to ${authority} in ${endTime - startTime}ms: ${submission.reportId}`);
      
      return {
        success: true,
        reportId: submission.reportId,
        submittedAt: submission.submittedAt
      };
      
    } catch (error) {
      this.logger.error(`Failed to report to tax authority ${authority}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async syncWithTaxAuthority(
    authority: string,
    fullSync: boolean = false
  ): Promise<{
    success: boolean;
    syncId?: string;
    recordsSynced?: number;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Syncing with tax authority: ${authority}`);

    try {
      const integration = this.integrations.get(authority);
      if (!integration) {
        return {
          success: false,
          error: `Tax authority integration not found: ${authority}`
        };
      }

      // Update sync status
      integration.syncStatus = SyncStatus.SYNCING;
      integration.lastSync = new Date();

      // Get last sync timestamp
      const lastSync = fullSync ? new Date(0) : integration.lastSync;

      // Fetch updates from tax authority
      const updates = await this.fetchTaxAuthorityUpdates(integration, lastSync);
      
      // Process updates
      const processedUpdates = await this.processTaxAuthorityUpdates(
        integration,
        updates
      );

      // Update local records
      await this.updateLocalRecords(integration, processedUpdates);

      // Update sync status
      integration.syncStatus = SyncStatus.ACTIVE;
      integration.lastSync = new Date();

      // Record sync history
      if (!this.syncHistory.has(authority)) {
        this.syncHistory.set(authority, []);
      }
      this.syncHistory.get(authority)!.push({
        syncId: `sync_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        startTime: new Date(startTime),
        endTime: new Date(),
        recordsSynced: processedUpdates.length,
        status: 'success',
        fullSync
      });

      const endTime = Date.now();
      
      this.logger.log(`Sync completed with ${authority} in ${endTime - startTime}ms: ${processedUpdates.length} records`);
      
      return {
        success: true,
        syncId: this.syncHistory.get(authority)!.slice(-1)[0].syncId,
        recordsSynced: processedUpdates.length
      };
      
    } catch (error) {
      this.logger.error(`Failed to sync with tax authority ${authority}:`, error);
      
      // Update sync status to error
      const integration = this.integrations.get(authority);
      if (integration) {
        integration.syncStatus = SyncStatus.ERROR;
      }

      return {
        success: false,
        error: error.message
      };
    }
  }

  async getTaxAuthorityRequirements(
    authority: string
  ): Promise<{
    reportingRequirements: any;
    dataFormats: any;
    thresholds: any;
    deadlines: any;
    encryption: any;
  }> {
    const integration = this.integrations.get(authority);
    if (!integration) {
      throw new Error(`Tax authority integration not found: ${authority}`);
    }

    try {
      // Fetch current requirements
      const requirements = await this.fetchTaxAuthorityRequirements(integration);
      
      return {
        reportingRequirements: requirements.reporting,
        dataFormats: requirements.formats,
        thresholds: requirements.thresholds,
        deadlines: requirements.deadlines,
        encryption: requirements.encryption
      };
      
    } catch (error) {
      this.logger.error(`Failed to fetch requirements from ${authority}:`, error);
      throw error;
    }
  }

  async validateReportFormat(
    authority: string,
    reportData: any
  ): Promise<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const integration = this.integrations.get(authority);
    if (!integration) {
      return {
        valid: false,
        errors: [`Tax authority integration not found: ${authority}`],
        warnings: []
      };
    }

    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate required fields
    const requiredFields = this.getRequiredFields(authority);
    for (const field of requiredFields) {
      if (!reportData[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Validate data formats
    const formatValidation = this.validateDataFormats(reportData, integration.dataMapping);
    if (!formatValidation.valid) {
      errors.push(...formatValidation.errors);
      warnings.push(...formatValidation.warnings);
    }

    // Validate thresholds
    const thresholdValidation = this.validateThresholds(reportData, integration);
    if (!thresholdValidation.valid) {
      warnings.push(...thresholdValidation.warnings);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  async getReportingStatus(
    authority: string
  ): Promise<{
    enabled: boolean;
    syncStatus: SyncStatus;
    lastSync: Date;
    pendingReports: number;
    recentReports: any[];
    errors: any[];
  }> {
    const integration = this.integrations.get(authority);
    if (!integration) {
      throw new Error(`Tax authority integration not found: ${authority}`);
    }

    const pendingReports = this.reportingQueue.get(authority)?.length || 0;
    const recentReports = this.reportingQueue.get(authority)?.slice(-10) || [];
    const errors = this.syncHistory.get(authority)?.filter(sync => sync.status === 'error').slice(-5) || [];

    return {
      enabled: integration.enabled,
      syncStatus: integration.syncStatus,
      lastSync: integration.lastSync,
      pendingReports,
      recentReports,
      errors
    };
  }

  async enableTaxAuthorityIntegration(
    authority: string,
    credentials: any
  ): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      const integration = this.integrations.get(authority);
      if (!integration) {
        return {
          success: false,
          error: `Tax authority integration not found: ${authority}`
        };
      }

      // Test authentication
      const authTest = await this.testAuthentication(integration, credentials);
      if (!authTest.success) {
        return {
          success: false,
          error: `Authentication failed: ${authTest.error}`
        };
      }

      // Update credentials and enable
      integration.authentication.credentials = credentials;
      integration.enabled = true;
      integration.syncStatus = SyncStatus.ACTIVE;

      this.logger.log(`Tax authority integration enabled: ${authority}`);
      
      return { success: true };
      
    } catch (error) {
      this.logger.error(`Failed to enable tax authority integration ${authority}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async disableTaxAuthorityIntegration(
    authority: string,
    reason: string
  ): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      const integration = this.integrations.get(authority);
      if (!integration) {
        return {
          success: false,
          error: `Tax authority integration not found: ${authority}`
        };
      }

      // Disable integration
      integration.enabled = false;
      integration.syncStatus = SyncStatus.DISABLED;

      // Record reason
      if (!this.syncHistory.has(authority)) {
        this.syncHistory.set(authority, []);
      }
      this.syncHistory.get(authority)!.push({
        timestamp: new Date(),
        action: 'disabled',
        reason,
        status: 'success'
      });

      this.logger.log(`Tax authority integration disabled: ${authority} - ${reason}`);
      
      return { success: true };
      
    } catch (error) {
      this.logger.error(`Failed to disable tax authority integration ${authority}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  private async prepareReportData(
    authority: string,
    alerts: ComplianceAlert[],
    evidencePackage: any,
    integration: TaxAuthorityIntegration
  ): Promise<any> {
    // Map data to tax authority format
    const reportData = {
      reportId: `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      authority,
      reportingEntity: 'compliance_system',
      alerts: alerts.map(alert => this.mapAlertToTaxAuthorityFormat(alert, integration.dataMapping)),
      evidence: this.mapEvidenceToTaxAuthorityFormat(evidencePackage, integration.dataMapping),
      summary: this.generateReportSummary(alerts, evidencePackage),
      metadata: {
        version: '1.0',
        format: integration.reportingFormat,
        encryption: integration.authentication.encryption.algorithm
      }
    };

    // Encrypt if required
    if (integration.authentication.encryption.enabled) {
      reportData.encrypted = await this.encryptReportData(reportData, integration.authentication.encryption);
    }

    return reportData;
  }

  private mapAlertToTaxAuthorityFormat(alert: ComplianceAlert, dataMapping: DataMapping): any {
    return {
      id: alert.id,
      type: dataMapping.alertTypes[alert.type] || alert.type,
      severity: dataMapping.riskLevels[alert.severity] || alert.severity,
      title: alert.title,
      description: alert.description,
      userId: alert.userId,
      jurisdiction: dataMapping.jurisdictions[alert.jurisdiction] || alert.jurisdiction,
      regulations: alert.regulations.map(reg => dataMapping.regulations[reg] || reg),
      detected: alert.detected,
      status: alert.status,
      assignedTo: alert.assignedTo,
      resolvedAt: alert.resolvedAt,
      evidence: this.mapEvidenceToTaxAuthorityFormat(alert.evidence, dataMapping)
    };
  }

  private mapEvidenceToTaxAuthorityFormat(evidence: any, dataMapping: DataMapping): any {
    return {
      transactionIds: evidence.transactionIds || [],
      ipAddresses: evidence.ipAddresses || [],
      deviceFingerprints: evidence.deviceFingerprints || [],
      behavioralData: evidence.behavioralData || {},
      crossBorderFlows: evidence.crossBorderFlows || [],
      evasionTechniques: evidence.evasionTechniques || [],
      riskScores: evidence.riskScores || [],
      timestamps: evidence.timestamps || [],
      screenshots: evidence.screenshots || [],
      logs: evidence.logs || []
    };
  }

  private generateReportSummary(alerts: ComplianceAlert[], evidencePackage: any): any {
    const severityBreakdown = {
      [RiskLevel.LOW]: alerts.filter(a => a.severity === RiskLevel.LOW).length,
      [RiskLevel.MEDIUM]: alerts.filter(a => a.severity === RiskLevel.MEDIUM).length,
      [RiskLevel.HIGH]: alerts.filter(a => a.severity === RiskLevel.HIGH).length,
      [RiskLevel.CRITICAL]: alerts.filter(a => a.severity === RiskLevel.CRITICAL).length
    };

    const typeBreakdown = {};
    alerts.forEach(alert => {
      typeBreakdown[alert.type] = (typeBreakdown[alert.type] || 0) + 1;
    });

    return {
      totalAlerts: alerts.length,
      severityBreakdown,
      typeBreakdown,
      timeRange: {
        start: alerts.length > 0 ? new Date(Math.min(...alerts.map(a => a.detected.getTime()))) : null,
        end: alerts.length > 0 ? new Date(Math.max(...alerts.map(a => a.detected.getTime()))) : null
      },
      averageRiskScore: alerts.length > 0 ? 
        alerts.reduce((sum, alert) => sum + (alert.evidence?.riskScores?.reduce((s: number, r: any) => s + r.score, 0) || 0), 0) / alerts.length : 0
    };
  }

  private async submitReport(integration: TaxAuthorityIntegration, reportData: any): Promise<{
    reportId: string;
    submittedAt: Date;
    confirmation?: any;
  }> {
    // Simulate API submission
    const reportId = reportData.reportId;
    const submittedAt = new Date();

    // In production, make actual API call
    const response = await this.makeAPICall(
      integration.apiEndpoint,
      'POST',
      reportData,
      {
        'Authorization': this.buildAuthHeader(integration.authentication),
        'Content-Type': 'application/json',
        'X-API-Version': '1.0'
      }
    );

    return {
      reportId,
      submittedAt,
      confirmation: response
    };
  }

  private async sendReportConfirmation(integration: TaxAuthorityIntegration, submission: any): Promise<void> {
    // Send confirmation notification
    this.logger.log(`Report confirmation sent for ${submission.reportId}`);
  }

  private async fetchTaxAuthorityUpdates(
    integration: TaxAuthorityIntegration,
    lastSync: Date
  ): Promise<any[]> {
    // Simulate fetching updates
    // In production, make actual API call
    return [
      {
        id: 'update_1',
        type: 'requirement_change',
        timestamp: new Date(),
        description: 'New reporting requirements',
        details: {
          oldThreshold: 10000,
          newThreshold: 5000,
          effectiveDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        }
      },
      {
        id: 'update_2',
        type: 'format_change',
        timestamp: new Date(),
        description: 'Updated data format requirements',
        details: {
          oldFormat: 'v1.0',
          newFormat: 'v2.0',
          migrationDeadline: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
        }
      }
    ];
  }

  private async processTaxAuthorityUpdates(
    integration: TaxAuthorityIntegration,
    updates: any[]
  ): Promise<any[]> {
    const processedUpdates = [];

    for (const update of updates) {
      try {
        const processed = await this.processUpdate(integration, update);
        processedUpdates.push(processed);
      } catch (error) {
        this.logger.error(`Failed to process update ${update.id}:`, error);
      }
    }

    return processedUpdates;
  }

  private async processUpdate(integration: TaxAuthorityIntegration, update: any): Promise<any> {
    switch (update.type) {
      case 'requirement_change':
        return await this.processRequirementChange(integration, update);
      case 'format_change':
        return await this.processFormatChange(integration, update);
      default:
        return { ...update, status: 'processed' };
    }
  }

  private async processRequirementChange(integration: TaxAuthorityIntegration, update: any): Promise<any> {
    // Update local requirements
    this.logger.log(`Processing requirement change: ${update.description}`);
    
    return {
      ...update,
      status: 'processed',
      action: 'requirements_updated'
    };
  }

  private async processFormatChange(integration: TaxAuthorityIntegration, update: any): Promise<any> {
    // Update data format mappings
    this.logger.log(`Processing format change: ${update.description}`);
    
    return {
      ...update,
      status: 'processed',
      action: 'format_updated'
    };
  }

  private async updateLocalRecords(
    integration: TaxAuthorityIntegration,
    updates: any[]
  ): Promise<void> {
    // Update local records based on tax authority updates
    for (const update of updates) {
      if (update.action === 'requirements_updated') {
        // Update requirements in local system
        await this.updateLocalRequirements(update.details);
      } else if (update.action === 'format_updated') {
        // Update format mappings
        await this.updateLocalFormatMappings(update.details);
      }
    }
  }

  private async updateLocalRequirements(details: any): Promise<void> {
    // Update local requirements database
    this.logger.log(`Updating local requirements:`, details);
  }

  private async updateLocalFormatMappings(details: any): Promise<void> {
    // Update local format mappings
    this.logger.log(`Updating local format mappings:`, details);
  }

  private getRequiredFields(authority: string): string[] {
    const fieldRequirements = {
      'IRS': ['reportId', 'timestamp', 'alerts', 'evidence', 'summary'],
      'HMRC': ['reference', 'period', 'transactions', 'suspicions', 'analysis'],
      'EU_TAX': ['submissionId', 'date', 'taxpayer', 'violations', 'penalties']
    };

    return fieldRequirements[authority] || ['reportId', 'timestamp', 'alerts', 'evidence'];
  }

  private validateDataFormats(reportData: any, dataMapping: DataMapping): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate alert types
    if (reportData.alerts) {
      for (const alert of reportData.alerts) {
        if (!dataMapping.alertTypes[alert.type]) {
          warnings.push(`Unknown alert type: ${alert.type}`);
        }
      }
    }

    // Validate risk levels
    if (reportData.alerts) {
      for (const alert of reportData.alerts) {
        if (!dataMapping.riskLevels[alert.severity]) {
          warnings.push(`Unknown risk level: ${alert.severity}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  private validateThresholds(reportData: any, integration: TaxAuthorityIntegration): {
    valid: boolean;
    warnings: string[];
  } {
    const warnings: string[] = [];

    // Check if report meets minimum thresholds
    const minAlerts = 1;
    if (reportData.alerts && reportData.alerts.length < minAlerts) {
      warnings.push(`Report has fewer than minimum alerts (${minAlerts})`);
    }

    return {
      valid: true,
      warnings
    };
  }

  private async testAuthentication(integration: TaxAuthorityIntegration, credentials: any): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      // Test authentication with tax authority
      const authHeader = this.buildAuthHeader({
        ...integration.authentication,
        credentials
      });

      const response = await this.makeAPICall(
        integration.apiEndpoint + '/auth/test',
        'POST',
        {},
        {
          'Authorization': authHeader,
          'Content-Type': 'application/json'
        }
      );

      return {
        success: response.status === 'success'
      };
      
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  private buildAuthHeader(authentication: any): string {
    switch (authentication.type) {
      case AuthType.API_KEY:
        return `Bearer ${authentication.credentials.apiKey}`;
      case AuthType.OAUTH:
        return `Bearer ${authentication.credentials.accessToken}`;
      case AuthType.CERTIFICATE:
        return `Certificate ${authentication.credentials.certificate}`;
      case AuthType.BASIC_AUTH:
        const encoded = Buffer.from(`${authentication.credentials.username}:${authentication.credentials.password}`).toString('base64');
        return `Basic ${encoded}`;
      default:
        return '';
    }
  }

  private async makeAPICall(url: string, method: string, data: any, headers: any): Promise<any> {
    // Simulate API call
    // In production, use actual HTTP client
    return {
      status: 'success',
      data: {},
      headers: {}
    };
  }

  private async encryptReportData(reportData: any, encryption: any): Promise<string> {
    // Encrypt report data
    // In production, use actual encryption library
    return JSON.stringify(reportData);
  }

  private async fetchTaxAuthorityRequirements(integration: TaxAuthorityIntegration): Promise<any> {
    // Fetch current requirements from tax authority
    // In production, make actual API call
    return {
      reporting: {
        frequency: 'daily',
        formats: ['json', 'xml'],
        encryption: 'required'
      },
      formats: {
        version: '2.0',
        schema: 'latest',
        validation: 'strict'
      },
      thresholds: {
        minAlerts: 1,
        maxFileSize: '10MB',
        maxReports: 100
      },
      deadlines: {
        daily: '23:59 UTC',
        weekly: 'Sunday 23:59 UTC',
        monthly: 'Last day 23:59 UTC'
      },
      encryption: {
        algorithm: 'AES-256',
        keyExchange: 'RSA-2048',
        certificate: 'required'
      }
    };
  }

  private initializeIntegrations(): void {
    // Initialize tax authority integrations
    const integrations = [
      {
        enabled: true,
        authority: 'IRS',
        reportingFormat: 'JSON',
        apiEndpoint: 'https://api.irs.gov/v2/compliance',
        authentication: {
          type: AuthType.API_KEY,
          credentials: {},
          encryption: {
            algorithm: 'AES-256',
            keyExchange: 'RSA-2048',
            certificate: 'cert.pem',
            enabled: true
          },
          rateLimit: {
            requests: 1000,
            window: 3600,
            blockDuration: 300
          }
        },
        dataMapping: {
          alertTypes: {
            [AlertType.REGULATORY_ARBITRAGE]: 'regulatory_arbitrage',
            [AlertType.TAX_EVASION]: 'tax_evasion',
            [AlertType.JURISDICTION_JUMPING]: 'jurisdiction_hopping',
            [AlertType.SUSPICIOUS_PATTERN]: 'suspicious_activity'
          },
          riskLevels: {
            [RiskLevel.LOW]: 'low',
            [RiskLevel.MEDIUM]: 'medium',
            [RiskLevel.HIGH]: 'high',
            [RiskLevel.CRITICAL]: 'critical'
          },
          jurisdictions: {
            'US': 'United States',
            'GB': 'United Kingdom',
            'DE': 'Germany',
            'FR': 'France'
          },
          transactionTypes: {
            'transfer': 'wire_transfer',
            'exchange': 'currency_exchange',
            'purchase': 'purchase_transaction'
          },
          customMappings: {}
        },
        reportingSchedule: {
          daily: true,
          weekly: false,
          monthly: false,
          quarterly: true,
          annual: false,
          realTime: false,
          immediate: true
        },
        lastSync: new Date(),
        syncStatus: SyncStatus.ACTIVE
      },
      {
        enabled: true,
        authority: 'HMRC',
        reportingFormat: 'XML',
        apiEndpoint: 'https://api.hmrc.gov.uk/v1/compliance',
        authentication: {
          type: AuthType.OAUTH,
          credentials: {},
          encryption: {
            algorithm: 'AES-256',
            keyExchange: 'ECDH',
            certificate: 'hmrc_cert.pem',
            enabled: true
          },
          rateLimit: {
            requests: 500,
            window: 3600,
            blockDuration: 600
          }
        },
        dataMapping: {
          alertTypes: {
            [AlertType.REGULATORY_ARBITRAGE]: 'regulatory_breach',
            [AlertType.TAX_EVASION]: 'tax_avoidance',
            [AlertType.JURISDICTION_JUMPING]: 'cross_border_activity'
          },
          riskLevels: {
            [RiskLevel.LOW]: 'minor',
            [RiskLevel.MEDIUM]: 'moderate',
            [RiskLevel.HIGH]: 'serious',
            [RiskLevel.CRITICAL]: 'severe'
          },
          jurisdictions: {
            'GB': 'United Kingdom',
            'US': 'United States',
            'IE': 'Ireland'
          },
          transactionTypes: {
            'transfer': 'electronic_transfer',
            'exchange': 'foreign_exchange'
          },
          customMappings: {}
        },
        reportingSchedule: {
          daily: false,
          weekly: true,
          monthly: true,
          quarterly: false,
          annual: false,
          realTime: false,
          immediate: false
        },
        lastSync: new Date(),
        syncStatus: SyncStatus.ACTIVE
      }
    ];

    integrations.forEach(integration => {
      this.integrations.set(integration.authority, integration);
    });

    this.logger.log(`Initialized ${integrations.length} tax authority integrations`);
  }

  async getAllIntegrations(): Promise<TaxAuthorityIntegration[]> {
    return Array.from(this.integrations.values());
  }

  async getIntegrationStatus(authority: string): Promise<TaxAuthorityIntegration | null> {
    return this.integrations.get(authority) || null;
  }

  async getReportingQueue(authority: string): Promise<any[]> {
    return this.reportingQueue.get(authority) || [];
  }

  async getSyncHistory(authority: string, limit: number = 50): Promise<any[]> {
    const history = this.syncHistory.get(authority) || [];
    return history.slice(-limit);
  }

  async clearReportingQueue(authority: string): Promise<void> {
    this.reportingQueue.delete(authority);
    this.logger.log(`Cleared reporting queue for ${authority}`);
  }
}
