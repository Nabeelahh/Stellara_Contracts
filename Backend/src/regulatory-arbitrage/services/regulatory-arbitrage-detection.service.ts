import { Injectable, Logger } from '@nestjs/common';
import {
  JurisdictionInferenceService,
  PatternRecognitionService,
  CrossBorderFlowAnalysisService,
  EvasionTechniqueLibraryService,
  DetectionRulesEngineService,
  AlertingReportingService,
  ComplianceTeamIntegrationService,
  TaxAuthorityCollaborationService
} from './services';
import {
  JurisdictionInference,
  UserBehavior,
  CrossBorderFlow,
  EvasionTechnique,
  ComplianceAlert,
  RiskLevel,
  AlertType
} from './interfaces/regulatory-arbitrage.interface';

@Injectable()
export class RegulatoryArbitrageDetectionService {
  private readonly logger = new Logger(RegulatoryArbitrageDetectionService.name);

  constructor(
    private readonly jurisdictionInference: JurisdictionInferenceService,
    private readonly patternRecognition: PatternRecognitionService,
    private readonly crossBorderFlowAnalysis: CrossBorderFlowAnalysisService,
    private readonly evasionTechniqueLibrary: EvasionTechniqueLibraryService,
    private readonly detectionRulesEngine: DetectionRulesEngineService,
    private readonly alertingReporting: AlertingReportingService,
    private readonly complianceTeamIntegration: ComplianceTeamIntegrationService,
    private readonly taxAuthorityCollaboration: TaxAuthorityCollaborationService
  ) {}

  async analyzeUser(
    userId: string,
    ipAddress: string,
    userAgent: string,
    behavior: UserBehavior,
    transactions: any[],
    networkData: any,
    deviceData: any
  ): Promise<{
    success: boolean;
    userId: string;
    jurisdictionInference?: JurisdictionInference;
    patternAnalysis?: any;
    flowAnalysis?: any;
    evasionDetection?: any;
    ruleEvaluation?: any;
    overallRiskScore: number;
    recommendations: any[];
    alerts?: ComplianceAlert[];
    errors?: string[];
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Starting comprehensive analysis for user ${userId}`);

    try {
      const results = {
        success: true,
        userId,
        errors: []
      };

      // Parallel execution of all analysis components
      const [
        jurisdictionInference,
        patternAnalysis,
        flowAnalysis,
        evasionDetection,
        ruleEvaluation
      ] = await Promise.allSettled([
        this.jurisdictionInference.inferJurisdiction(userId, ipAddress, userAgent, behavior),
        this.patternRecognition.analyzeUserBehavior(behavior),
        this.crossBorderFlowAnalysis.analyzeCrossBorderFlows(userId, transactions),
        this.evasionTechniqueLibrary.detectEvasionTechniques(behavior, transactions, networkData, deviceData),
        this.detectionRulesEngine.evaluateUser(userId, behavior, transactions, networkData, deviceData)
      ]);

      // Extract results from settled promises
      if (jurisdictionInference.status === 'fulfilled') {
        results.jurisdictionInference = jurisdictionInference.value;
      } else {
        results.errors.push(`Jurisdiction inference failed: ${jurisdictionInference.reason}`);
      }

      if (patternAnalysis.status === 'fulfilled') {
        results.patternAnalysis = patternAnalysis.value;
      } else {
        results.errors.push(`Pattern recognition failed: ${patternAnalysis.reason}`);
      }

      if (flowAnalysis.status === 'fulfilled') {
        results.flowAnalysis = flowAnalysis.value;
      } else {
        results.errors.push(`Cross-border flow analysis failed: ${flowAnalysis.reason}`);
      }

      if (evasionDetection.status === 'fulfilled') {
        results.evasionDetection = evasionDetection.value;
      } else {
        results.errors.push(`Evasion technique detection failed: ${evasionDetection.reason}`);
      }

      if (ruleEvaluation.status === 'fulfilled') {
        results.ruleEvaluation = ruleEvaluation.value;
      } else {
        results.errors.push(`Rule evaluation failed: ${ruleEvaluation.reason}`);
      }

      // Calculate overall risk score
      results.overallRiskScore = this.calculateOverallRiskScore(
        results.jurisdictionInference,
        results.patternAnalysis,
        results.flowAnalysis,
        results.evasionDetection,
        results.ruleEvaluation
      );

      // Generate recommendations
      results.recommendations = this.generateRecommendations(results);

      // Generate alerts for high-risk findings
      if (results.overallRiskScore > 70) {
        results.alerts = await this.generateAlerts(userId, results);
      }

      const endTime = Date.now();
      
      this.logger.log(`Comprehensive analysis completed for user ${userId} in ${endTime - startTime}ms`);
      
      return results;
      
    } catch (error) {
      this.logger.error(`Failed to analyze user ${userId}:`, error);
      return {
        success: false,
        userId,
        errors: [error.message]
      };
    }
  }

  async detectRegulatoryArbitrage(
    userId: string,
    transactions: any[]
  ): Promise<{
      detected: boolean;
      arbitrageTypes: string[];
      jurisdictions: string[];
      profit: number;
      riskScore: number;
      evidence: any;
      recommendations: any[];
    }> {
    const startTime = Date.now();
    
    this.logger.log(`Detecting regulatory arbitrage for user ${userId}`);

    try {
      // Analyze cross-border flows
      const flowAnalysis = await this.crossBorderFlowAnalysis.analyzeCrossBorderFlows(userId, transactions);
      
      const arbitrageDetections = flowAnalysis.arbitrageDetections || [];
      
      if (arbitrageDetections.length === 0) {
        return {
          detected: false,
          arbitrageTypes: [],
          jurisdictions: [],
          profit: 0,
          riskScore: 0,
          evidence: {},
          recommendations: []
        };
      }

      // Extract arbitrage information
      const arbitrageTypes = [...new Set(arbitrageDetections.map(d => d.type))];
      const jurisdictions = [...new Set(arbitrageDetections.flatMap(d => d.jurisdictions))];
      const totalProfit = arbitrageDetections.reduce((sum, d) => sum + d.profit, 0);
      const averageRiskScore = arbitrageDetections.reduce((sum, d) => sum + d.riskScore, 0) / arbitrageDetections.length;

      // Generate evidence
      const evidence = {
        arbitrageDetections,
        flowAnalysis: flowAnalysis.analysis,
        suspiciousPatterns: this.identifySuspiciousPatterns(arbitrageDetections),
        jurisdictionDifferences: this.analyzeJurisdictionDifferences(jurisdictions)
      };

      // Generate recommendations
      const recommendations = this.generateArbitrageRecommendations(arbitrageDetections, evidence);

      const endTime = Date.now();
      
      this.logger.log(`Regulatory arbitrage detection completed for user ${userId} in ${endTime - startTime}ms`);
      
      return {
        detected: true,
        arbitrageTypes,
        jurisdictions,
        profit: totalProfit,
        riskScore: averageRiskScore,
        evidence,
        recommendations
      };
      
    } catch (error) {
      this.logger.error(`Failed to detect regulatory arbitrage for user ${userId}:`, error);
      throw error;
    }
  }

  async generateComplianceReport(
    filters: any
  ): Promise<{
    success: boolean;
    reportId?: string;
    generatedAt?: Date;
    summary?: any;
    details?: any;
    recommendations?: any;
    errors?: string[];
  }> {
    const startTime = Date.now();
    
    this.logger.log('Generating compliance report');

    try {
      // Get alerts based on filters
      const alertData = await this.alertingReporting.getAlerts(filters);
      
      // Generate comprehensive report
      const report = await this.alertingReporting.generateComplianceReport(filters);
      
      const endTime = Date.now();
      
      this.logger.log(`Compliance report generated in ${endTime - startTime}ms`);
      
      return {
        success: true,
        reportId: report.reportId,
        generatedAt: report.generatedAt,
        summary: report.summary,
        details: report.details,
        recommendations: report.recommendations
      };
      
    } catch (error) {
      this.logger.error('Failed to generate compliance report:', error);
      return {
        success: false,
        errors: [error.message]
      };
    }
  }

  async escalateAlert(
    alertId: string,
    reason: string,
    escalatedTo?: string
  ): Promise<{
      success: boolean;
      escalatedTo?: string;
      escalatedAt?: Date;
      reason?: string;
      error?: string;
    }> {
    const startTime = Date.now();
    
    this.logger.log(`Escalating alert ${alertId}`);

    try {
      // Get alert details
      const alert = await this.alertingReporting.getAlertDetails(alertId);
      
      if (!alert) {
        return {
          success: false,
          error: `Alert not found: ${alertId}`
        };
      }

      // Check if alert should be escalated
      if (alert.severity !== RiskLevel.HIGH && alert.severity !== RiskLevel.CRITICAL) {
        return {
          success: false,
          error: 'Alert severity too low for escalation'
        };
      }

      // Determine escalation target
      const target = escalatedTo || this.determineEscalationTarget(alert);

      // Perform escalation
      await this.complianceTeamIntegration.escalateAlert(alertId, reason, target);

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} escalated in ${endTime - startTime}ms`);
      
      return {
        success: true,
        escalatedTo: target,
        escalatedAt: new Date(),
        reason
      };
      
    } catch (error) {
      this.logger.error(`Failed to escalate alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
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
      // Submit report to tax authority
      const result = await this.taxAuthorityCollaboration.reportToTaxAuthority(
        authority,
        alerts,
        evidencePackage,
        priority
      );

      const endTime = Date.now();
      
      this.logger.log(`Report submitted to ${authority} in ${endTime - startTime}ms`);
      
      return result;
      
    } catch (error) {
      this.logger.error(`Failed to report to tax authority ${authority}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async getSystemHealth(): Promise<{
    overallStatus: string;
    services: any;
    lastCheck: Date;
  }> {
    try {
      // Check health of all services
      const [
        jurisdictionHealth,
        patternHealth,
        flowHealth,
        evasionHealth,
        rulesHealth,
        alertHealth,
        teamHealth,
        taxHealth
      ] = await Promise.allSettled([
        this.checkServiceHealth('jurisdictionInference'),
        this.checkServiceHealth('patternRecognition'),
        this.checkServiceHealth('crossBorderFlowAnalysis'),
        this.checkServiceHealth('evasionTechniqueLibrary'),
        this.checkServiceHealth('detectionRulesEngine'),
        this.checkServiceHealth('alertingReporting'),
        this.checkServiceHealth('complianceTeamIntegration'),
        this.checkServiceHealth('taxAuthorityCollaboration')
      ]);

      const services = {
        jurisdictionInference: jurisdictionHealth.status === 'fulfilled' ? jurisdictionHealth.value : { status: 'error', error: jurisdictionHealth.reason },
        patternRecognition: patternHealth.status === 'fulfilled' ? patternHealth.value : { status: 'error', error: patternHealth.reason },
        crossBorderFlowAnalysis: flowHealth.status === 'fulfilled' ? flowHealth.value : { status: 'error', error: flowHealth.reason },
        evasionTechniqueLibrary: evasionHealth.status === 'fulfilled' ? evasionHealth.value : { status: 'error', error: evasionHealth.reason },
        detectionRulesEngine: rulesHealth.status === 'fulfilled' ? rulesHealth.value : { status: 'error', error: rulesHealth.reason },
        alertingReporting: alertHealth.status === 'fulfilled' ? alertHealth.value : { status: 'error', error: alertHealth.reason },
        complianceTeamIntegration: teamHealth.status === 'fulfilled' ? teamHealth.value : { status: 'error', error: teamHealth.reason },
        taxAuthorityCollaboration: taxHealth.status === 'fulfilled' ? taxHealth.value : { status: 'error', error: taxHealth.reason }
      };

      // Determine overall status
      const overallStatus = this.determineOverallHealth(services);

      return {
        overallStatus,
        services,
        lastCheck: new Date()
      };
      
    } catch (error) {
      this.logger.error('Failed to get system health:', error);
      return {
        overallStatus: 'error',
        services: {},
        lastCheck: new Date()
      };
    }
  }

  private calculateOverallRiskScore(
    jurisdictionInference: any,
    patternAnalysis: any,
    flowAnalysis: any,
    evasionDetection: any,
    ruleEvaluation: any
  ): number {
    let totalScore = 0;
    let weightSum = 0;

    // Weight each component
    const weights = {
      jurisdiction: 0.15,
      pattern: 0.20,
      flow: 0.25,
      evasion: 0.25,
      rules: 0.15
    };

    if (jurisdictionInference) {
      totalScore += (jurisdictionInference.riskScore || 0) * weights.jurisdiction;
      weightSum += weights.jurisdiction;
    }

    if (patternAnalysis) {
      totalScore += (patternAnalysis.riskScore || 0) * weights.pattern;
      weightSum += weights.pattern;
    }

    if (flowAnalysis) {
      totalScore += (flowAnalysis.riskScore || 0) * weights.flow;
      weightSum += weights.flow;
    }

    if (evasionDetection) {
      totalScore += (evasionDetection.riskScore || 0) * weights.evasion;
      weightSum += weights.evasion;
    }

    if (ruleEvaluation) {
      totalScore += (ruleEvaluation.riskScore || 0) * weights.rules;
      weightSum += weights.rules;
    }

    return weightSum > 0 ? totalScore / weightSum : 0;
  }

  private generateRecommendations(results: any): any[] {
    const recommendations = [];

    // Based on risk score
    if (results.overallRiskScore > 80) {
      recommendations.push({
        type: 'immediate_investigation',
        priority: 'critical',
        description: 'Immediate investigation required due to high risk score',
        actions: ['Assign to senior compliance officer', 'Initiate detailed investigation', 'Consider account suspension']
      });
    } else if (results.overallRiskScore > 60) {
      recommendations.push({
        type: 'enhanced_monitoring',
        priority: 'high',
        description: 'Enhanced monitoring recommended',
        actions: ['Increase monitoring frequency', 'Add behavioral analysis', 'Review recent transactions']
      });
    }

    // Based on specific findings
    if (results.evasionDetection?.detectedTechniques?.length > 0) {
      recommendations.push({
        type: 'evasion_techniques',
        priority: 'high',
        description: 'Evasion techniques detected',
        actions: ['Implement countermeasures', 'Update detection rules', 'Enhance privacy tool detection']
      });
    }

    if (results.flowAnalysis?.arbitrageDetections?.length > 0) {
      recommendations.push({
        type: 'regulatory_arbitrage',
        priority: 'high',
        description: 'Regulatory arbitrage detected',
        actions: ['Investigate arbitrage patterns', 'Review jurisdictional compliance', 'Consider reporting to authorities']
      });
    }

    return recommendations;
  }

  private async generateAlerts(userId: string, results: any): Promise<ComplianceAlert[]> {
    const alerts: ComplianceAlert[] = [];

    // Generate alerts for high-risk findings
    if (results.evasionDetection?.riskScore > 70) {
      const alert = await this.alertingReporting.createAlert(
        userId,
        AlertType.PRIVACY_TOOL_USAGE,
        RiskLevel.HIGH,
        'Privacy Tools Detected',
        'Multiple privacy tools or evasion techniques detected',
        results.evasionDetection.evidence
      );
      alerts.push(alert);
    }

    if (results.flowAnalysis?.riskScore > 70) {
      const alert = await this.alertingReporting.createAlert(
        userId,
        AlertType.REGULATORY_ARBITRAGE,
        RiskLevel.HIGH,
        'Regulatory Arbitrage Detected',
        'Regulatory arbitrage patterns detected',
        results.flowAnalysis.evidence
      );
      alerts.push(alert);
    }

    if (results.ruleEvaluation?.riskScore > 80) {
      const alert = await this.alertingReporting.createAlert(
        userId,
        AlertType.SUSPICIOUS_PATTERN,
        RiskLevel.CRITICAL,
        'Critical Risk Pattern',
        'Critical risk patterns detected through rule evaluation',
        results.ruleEvaluation.evidence
      );
      alerts.push(alert);
    }

    return alerts;
  }

  private identifySuspiciousPatterns(arbitrageDetections: any[]): any[] {
    const patterns = [];

    // Look for common arbitrage patterns
    const jurisdictionCounts = {};
    arbitrageDetections.forEach(detection => {
      detection.jurisdictions.forEach(jurisdiction => {
        jurisdictionCounts[jurisdiction] = (jurisdictionCounts[jurisdiction] || 0) + 1;
      });
    });

    // Identify jurisdiction shopping
    if (Object.keys(jurisdictionCounts).length > 3) {
      patterns.push({
        type: 'jurisdiction_shopping',
        description: 'User actively shopping across multiple jurisdictions',
        severity: 'high'
      });
    }

    return patterns;
  }

  private analyzeJurisdictionDifferences(jurisdictions: string[]): any {
    // Analyze regulatory differences between jurisdictions
    const differences = [];

    for (let i = 0; i < jurisdictions.length - 1; i++) {
      for (let j = i + 1; j < jurisdictions.length; j++) {
        const diff = this.getRegulatoryDifference(jurisdictions[i], jurisdictions[j]);
        if (diff.hasSignificantDifferences) {
          differences.push({
            from: jurisdictions[i],
            to: jurisdictions[j],
            differences: diff.differences,
            arbitrageOpportunity: diff.arbitrageOpportunity
          });
        }
      }
    }

    return differences;
  }

  private getRegulatoryDifference(jurisdiction1: string, jurisdiction2: string): any {
    // Simplified regulatory difference analysis
    const regulatoryMatrix = {
      'US': { kyc: 'strict', reporting: 'daily', privacy: 'moderate' },
      'GB': { kyc: 'strict', reporting: 'weekly', privacy: 'high' },
      'DE': { kyc: 'moderate', reporting: 'monthly', privacy: 'high' },
      'FR': { kyc: 'moderate', reporting: 'monthly', privacy: 'very_high' }
    };

    const reg1 = regulatoryMatrix[jurisdiction1];
    const reg2 = regulatoryMatrix[jurisdiction2];

    if (!reg1 || !reg2) {
      return { hasSignificantDifferences: false };
    }

    const differences = [];
    let arbitrageOpportunity = false;

    if (reg1.kyc !== reg2.kyc) {
      differences.push(`KYC requirements: ${reg1.kyc} vs ${reg2.kyc}`);
      if (reg1.kyc === 'moderate' && reg2.kyc === 'strict') {
        arbitrageOpportunity = true;
      }
    }

    if (reg1.reporting !== reg2.reporting) {
      differences.push(`Reporting frequency: ${reg1.reporting} vs ${reg2.reporting}`);
    }

    if (reg1.privacy !== reg2.privacy) {
      differences.push(`Privacy standards: ${reg1.privacy} vs ${reg2.privacy}`);
    }

    return {
      hasSignificantDifferences: differences.length > 0 || arbitrageOpportunity,
      differences,
      arbitrageOpportunity
    };
  }

  private generateArbitrageRecommendations(arbitrageDetections: any[], evidence: any): any[] {
    const recommendations = [];

    // Based on arbitrage type
    const arbitrageTypes = [...new Set(arbitrageDetections.map(d => d.type))];

    if (arbitrageTypes.includes('regulatory')) {
      recommendations.push({
        type: 'regulatory_compliance',
        priority: 'high',
        description: 'Address regulatory arbitrage through enhanced compliance',
        actions: [
          'Implement jurisdiction-based restrictions',
          'Enhance monitoring across jurisdictions',
          'Consider reporting to relevant authorities'
        ]
      });
    }

    if (arbitrageTypes.includes('tax')) {
      recommendations.push({
        type: 'tax_authority_reporting',
        priority: 'critical',
        description: 'Report tax arbitrage to appropriate authorities',
        actions: [
          'Prepare comprehensive evidence package',
          'File required reports with tax authorities',
          'Coordinate with legal team'
        ]
      });
    }

    return recommendations;
  }

  private determineEscalationTarget(alert: ComplianceAlert): string {
    // Determine escalation target based on alert type and severity
    const escalationMatrix = {
      [AlertType.REGULATORY_ARBITRAGE]: {
        [RiskLevel.HIGH]: 'senior_regulatory_specialist',
        [RiskLevel.CRITICAL]: 'head_of_compliance'
      },
      [AlertType.TAX_EVASION]: {
        [RiskLevel.HIGH]: 'senior_tax_specialist',
        [RiskLevel.CRITICAL]: 'head_of_tax_compliance'
      }
    };

    return escalationMatrix[alert.type]?.[alert.severity] || 'senior_compliance_officer';
  }

  private async checkServiceHealth(serviceName: string): Promise<any> {
    try {
      // Mock health check - in production, implement actual health checks
      return {
        status: 'fulfilled',
        value: {
          status: 'healthy',
          responseTime: Math.random() * 100 + 50,
          lastCheck: new Date()
        }
      };
    } catch (error) {
      return {
        status: 'rejected',
        reason: error.message
      };
    }
  }

  private determineOverallHealth(services: any): string {
    const serviceStatuses = Object.values(services);
    const healthyCount = serviceStatuses.filter(service => service.status === 'healthy').length;
    const totalCount = serviceStatuses.length;

    if (healthyCount === totalCount) {
      return 'healthy';
    } else if (healthyCount >= totalCount * 0.8) {
      return 'degraded';
    } else if (healthyCount >= totalCount * 0.5) {
      return 'unhealthy';
    } else {
      return 'critical';
    }
  }
}
