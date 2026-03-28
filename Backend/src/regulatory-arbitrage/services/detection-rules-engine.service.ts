import { Injectable, Logger } from '@nestjs/common';
import {
  DetectionRules,
  DetectionRule,
  Version,
  JurisdictionProfile,
  EvasionTechnique,
  RiskLevel,
  SuspiciousIndicatorType,
  AlertType,
  Priority
} from '../interfaces/regulatory-arbitrage.interface';

@Injectable()
export class DetectionRulesEngineService {
  private readonly logger = new Logger(DetectionRulesEngineService.name);
  private readonly activeRules = new Map<string, DetectionRule>();
  private readonly ruleHistory = new Map<string, Version[]>();
  private readonly ruleExecutions = new Map<string, any[]>();
  private readonly monthlyUpdates = new Map<string, Date>();

  constructor() {
    this.initializeDetectionRules();
    this.scheduleMonthlyUpdates();
  }

  async evaluateUser(
    userId: string,
    behavior: any,
    transactions: any[],
    networkData: any,
    deviceData: any,
    jurisdiction?: JurisdictionProfile
  ): Promise<{
    triggeredRules: DetectionRule[];
    riskScore: number;
    recommendations: any[];
    alerts: any[];
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Evaluating detection rules for user ${userId}`);

    try {
      const triggeredRules: DetectionRule[] = [];
      const recommendations: any[] = [];
      const alerts: any[] = [];
      let totalRiskScore = 0;

      // Get all active rules
      const allRules = Array.from(this.activeRules.values());

      // Evaluate each rule
      for (const rule of allRules) {
        if (!rule.enabled) continue;

        const evaluation = await this.evaluateRule(
          rule,
          userId,
          behavior,
          transactions,
          networkData,
          deviceData,
          jurisdiction
        );

        if (evaluation.triggered) {
          triggeredRules.push(rule);
          totalRiskScore += rule.weight * evaluation.confidence;

          // Generate recommendation
          const recommendation = this.generateRecommendation(rule, evaluation);
          if (recommendation) {
            recommendations.push(recommendation);
          }

          // Generate alert if high risk
          if (rule.weight >= 0.7) {
            const alert = this.generateAlert(rule, evaluation, userId);
            alerts.push(alert);
          }

          // Record rule execution
          this.recordRuleExecution(rule.id, evaluation);
        }
      }

      const endTime = Date.now();
      
      this.logger.log(`Rule evaluation completed for user ${userId} in ${endTime - startTime}ms`);
      
      return {
        triggeredRules,
        riskScore: Math.min(100, totalRiskScore),
        recommendations,
        alerts
      };
      
    } catch (error) {
      this.logger.error(`Failed to evaluate detection rules for user ${userId}:`, error);
      throw error;
    }
  }

  private async evaluateRule(
    rule: DetectionRule,
    userId: string,
    behavior: any,
    transactions: any[],
    networkData: any,
    deviceData: any,
    jurisdiction?: JurisdictionProfile
  ): Promise<{
    triggered: boolean;
    confidence: number;
    evidence: any;
    details: string;
  }> {
    try {
      // Parse and evaluate rule condition
      const context = this.buildEvaluationContext(
        userId,
        behavior,
        transactions,
        networkData,
        deviceData,
        jurisdiction
      );

      const result = await this.evaluateCondition(rule.condition, context);
      
      // Check time window
      const withinTimeWindow = this.checkTimeWindow(rule, context);
      
      // Check threshold
      const thresholdMet = this.checkThreshold(rule, result.value);

      const triggered = result.success && withinTimeWindow && thresholdMet;

      return {
        triggered,
        confidence: result.confidence || 0.5,
        evidence: result.evidence || context,
        details: result.details || `Rule ${rule.name} ${triggered ? 'triggered' : 'not triggered'}`
      };
      
    } catch (error) {
      this.logger.error(`Failed to evaluate rule ${rule.id}:`, error);
      return {
        triggered: false,
        confidence: 0,
        evidence: {},
        details: `Rule evaluation failed: ${error.message}`
      };
    }
  }

  private buildEvaluationContext(
    userId: string,
    behavior: any,
    transactions: any[],
    networkData: any,
    deviceData: any,
    jurisdiction?: JurisdictionProfile
  ): any {
    return {
      user: {
        id: userId,
        behavior,
        riskScore: behavior.behaviorScore || 0,
        anomalies: behavior.anomalies || []
      },
      transactions: {
        list: transactions,
        count: transactions.length,
        totalAmount: transactions.reduce((sum: number, tx: any) => sum + (tx.amount || 0), 0),
        averageAmount: transactions.length > 0 ? 
          transactions.reduce((sum: number, tx: any) => sum + (tx.amount || 0), 0) / transactions.length : 0,
        currencies: [...new Set(transactions.map((tx: any) => tx.currency).filter(Boolean))],
        destinations: [...new Set(transactions.map((tx: any) => tx.destination).filter(Boolean))],
        timeSpan: transactions.length > 1 ? 
          Math.max(...transactions.map((tx: any) => tx.timestamp)) - 
          Math.min(...transactions.map((tx: any) => tx.timestamp)) : 0
      },
      network: {
        ipAddress: networkData.ipAddress,
        country: networkData.country,
        vpn: networkData.vpn || false,
        proxy: networkData.proxy || false,
        tor: networkData.tor || false,
        privacyTools: networkData.privacyTools || []
      },
      device: {
        fingerprint: deviceData.fingerprint,
        privacyTools: deviceData.privacyTools || [],
        virtualization: deviceData.virtualization || false,
        mobile: deviceData.mobile || false
      },
      jurisdiction: jurisdiction || null,
      timestamp: Date.now(),
      timeWindow: {
        start: Date.now() - (24 * 60 * 60 * 1000), // 24 hours ago
        end: Date.now()
      }
    };
  }

  private async evaluateCondition(condition: string, context: any): Promise<{
    success: boolean;
    value: any;
    confidence: number;
    evidence?: any;
    details?: string;
  }> {
    try {
      // Simple condition evaluation (in production, use a proper expression parser)
      const result = this.evaluateSimpleCondition(condition, context);
      
      return {
        success: result.success,
        value: result.value,
        confidence: result.confidence || 0.5,
        evidence: result.evidence,
        details: result.details
      };
      
    } catch (error) {
      this.logger.error(`Failed to evaluate condition: ${condition}`, error);
      return {
        success: false,
        value: null,
        confidence: 0,
        details: `Condition evaluation failed: ${error.message}`
      };
    }
  }

  private evaluateSimpleCondition(condition: string, context: any): any {
    // Simplified condition evaluation
    // In production, implement a proper expression parser and evaluator
    
    // Privacy tools detection
    if (condition.includes('privacy_tools.enabled')) {
      const privacyTools = context.network.privacyTools || context.device.privacyTools || [];
      return {
        success: privacyTools.length > 0,
        value: privacyTools.length,
        confidence: 0.8,
        evidence: { privacyTools }
      };
    }

    // VPN detection
    if (condition.includes('network.vpn')) {
      return {
        success: context.network.vpn === true,
        value: context.network.vpn,
        confidence: 0.9,
        evidence: { vpn: context.network.vpn }
      };
    }

    // Transaction count detection
    if (condition.includes('transactions.count')) {
      const count = context.transactions.count;
      const threshold = this.extractThreshold(condition);
      return {
        success: count > threshold,
        value: count,
        confidence: 0.7,
        evidence: { count, threshold }
      };
    }

    // Transaction amount detection
    if (condition.includes('transactions.totalAmount')) {
      const totalAmount = context.transactions.totalAmount;
      const threshold = this.extractThreshold(condition);
      return {
        success: totalAmount > threshold,
        value: totalAmount,
        confidence: 0.8,
        evidence: { totalAmount, threshold }
      };
    }

    // Jurisdiction risk detection
    if (condition.includes('jurisdiction.riskLevel')) {
      if (!context.jurisdiction) {
        return {
          success: false,
          value: null,
          confidence: 0,
          details: 'No jurisdiction data available'
        };
      }
      
      const riskLevel = context.jurisdiction.riskLevel;
      const expectedLevel = this.extractRiskLevel(condition);
      
      return {
        success: riskLevel === expectedLevel,
        value: riskLevel,
        confidence: 0.9,
        evidence: { riskLevel, expectedLevel }
      };
    }

    // User behavior score detection
    if (condition.includes('user.behavior.riskScore')) {
      const behaviorScore = context.user.behavior.riskScore;
      const threshold = this.extractThreshold(condition);
      
      return {
        success: behaviorScore > threshold,
        value: behaviorScore,
        confidence: 0.7,
        evidence: { behaviorScore, threshold }
      };
    }

    // Multiple jurisdictions detection
    if (condition.includes('jurisdiction_changes')) {
      const destinations = context.transactions.destinations;
      const threshold = this.extractThreshold(condition);
      
      return {
        success: destinations.length > threshold,
        value: destinations.length,
        confidence: 0.8,
        evidence: { destinations, threshold }
      };
    }

    // Time-based detection
    if (condition.includes('user.timeWindow')) {
      const timeSpan = context.transactions.timeSpan;
      const threshold = this.extractThreshold(condition);
      
      return {
        success: timeSpan < threshold,
        value: timeSpan,
        confidence: 0.6,
        evidence: { timeSpan, threshold }
      };
    }

    // Default case
    return {
      success: false,
      value: null,
      confidence: 0,
      details: `Condition not recognized: ${condition}`
    };
  }

  private extractThreshold(condition: string): number {
    // Extract threshold value from condition
    const match = condition.match(/>\s*(\d+)/);
    return match ? parseInt(match[1]) : 0;
  }

  private extractRiskLevel(condition: string): string {
    // Extract risk level from condition
    const match = condition.match(/==\s*['"]([^'"]+)['"]/);
    return match ? match[1] : '';
  }

  private checkTimeWindow(rule: DetectionRule, context: any): boolean {
    if (!rule.timeWindow || rule.timeWindow === 0) return true;
    
    const now = Date.now();
    const windowStart = now - (rule.timeWindow * 1000);
    
    // Check if there's relevant activity within the time window
    const hasRecentActivity = 
      (context.transactions.timeSpan > 0 && 
       (now - context.transactions.timeSpan) <= rule.timeWindow * 1000) ||
      (context.user.anomalies.length > 0 &&
       context.user.anomalies.some((anomaly: any) => 
         (now - anomaly.detected.getTime()) <= rule.timeWindow * 1000
       ));
    
    return hasRecentActivity;
  }

  private checkThreshold(rule: DetectionRule, result: any): boolean {
    if (rule.threshold === undefined) return true;
    
    if (typeof result === 'number') {
      return result >= rule.threshold;
    }
    
    if (typeof result === 'boolean') {
      return result === true;
    }
    
    return false;
  }

  private generateRecommendation(rule: DetectionRule, evaluation: any): any {
    const recommendations = {
      [SuspiciousIndicatorType.PRIVACY_TOOL_USAGE]: {
        type: 'enhanced_monitoring',
        priority: Priority.MEDIUM,
        description: 'Implement enhanced monitoring for privacy tool usage',
        actions: [
          'Add privacy tool detection to monitoring',
          'Implement behavioral analysis',
          'Review user activity patterns'
        ],
        resources: ['monitoring_system', 'behavioral_analytics'],
        deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        automated: false
      },
      [SuspiciousIndicatorType.JURISDICTION_JUMPING]: {
        type: 'geographic_restrictions',
        priority: Priority.HIGH,
        description: 'Implement geographic restrictions and additional verification',
        actions: [
          'Restrict access from suspicious jurisdictions',
          'Require additional identity verification',
          'Implement device fingerprinting'
        ],
        resources: ['compliance_system', 'verification_services'],
        deadline: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days
        automated: false
      },
      [SuspiciousIndicatorType.ROUND_TRIPPING]: {
        type: 'investigation',
        priority: Priority.HIGH,
        description: 'Investigate potential round-tripping activity',
        actions: [
          'Analyze transaction patterns',
          'Review intermediary relationships',
          'Implement circular transaction detection'
        ],
        resources: ['investigation_team', 'transaction_monitoring'],
        deadline: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), // 2 days
        automated: false
      },
      [SuspiciousIndicatorType.STRUCTURING]: {
        type: 'reporting',
        priority: Priority.MEDIUM,
        description: 'Enhance reporting requirements for structured transactions',
        actions: [
          'Implement aggregation-based reporting',
          'Review transaction limits',
          'Enhance monitoring systems'
        ],
        resources: ['compliance_system', 'reporting_tools'],
        deadline: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000), // 5 days
        automated: false
      }
    };

    return recommendations[rule.type] || null;
  }

  private generateAlert(rule: DetectionRule, evaluation: any, userId: string): any {
    const alertTypes = {
      [SuspiciousIndicatorType.PRIVACY_TOOL_USAGE]: AlertType.PRIVACY_TOOL_USAGE,
      [SuspiciousIndicatorType.JURISDICTION_JUMPING]: AlertType.JURISDICTION_JUMPING,
      [SuspiciousIndicatorType.ROUND_TRIPPING]: AlertType.STRUCTURED_TRANSACTIONS,
      [SuspiciousIndicatorType.STRUCTURING]: AlertType.STRUCTURED_TRANSACTIONS,
      [SuspiciousIndicatorType.AUTOMATED_BEHAVIOR]: AlertType.SUSPICIOUS_PATTERN,
      [SuspiciousIndicatorType.SUSPICIOUS_TRANSACTION_PATTERN]: AlertType.SUSPICIOUS_PATTERN
    };

    return {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type: alertTypes[rule.type] || AlertType.SUSPICIOUS_PATTERN,
      severity: this.getAlertSeverity(rule.weight),
      title: `Suspicious Activity Detected: ${rule.name}`,
      description: `Detection rule "${rule.name}" was triggered with confidence ${evaluation.confidence}`,
      evidence: evaluation.evidence,
      detected: new Date(),
      status: 'open'
    };
  }

  private getAlertSeverity(weight: number): RiskLevel {
    if (weight >= 0.9) return RiskLevel.CRITICAL;
    if (weight >= 0.7) return RiskLevel.HIGH;
    if (weight >= 0.5) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private recordRuleExecution(ruleId: string, evaluation: any): void {
    if (!this.ruleExecutions.has(ruleId)) {
      this.ruleExecutions.set(ruleId, []);
    }
    
    this.ruleExecutions.get(ruleId)!.push({
      timestamp: new Date(),
      result: evaluation,
      success: evaluation.triggered
    });
    
    // Keep only last 1000 executions per rule
    const executions = this.ruleExecutions.get(ruleId)!;
    if (executions.length > 1000) {
      this.ruleExecutions.set(ruleId, executions.slice(-1000));
    }
  }

  async updateDetectionRules(
    updates: {
      add?: DetectionRule[];
      update?: DetectionRule[];
      remove?: string[];
    }
  ): Promise<void> {
    const startTime = Date.now();
    
    this.logger.log('Updating detection rules');

    try {
      // Add new rules
      if (updates.add) {
        for (const rule of updates.add) {
          this.activeRules.set(rule.id, rule);
          this.logger.log(`Added detection rule: ${rule.id}`);
        }
      }

      // Update existing rules
      if (updates.update) {
        for (const rule of updates.update) {
          const existingRule = this.activeRules.get(rule.id);
          if (existingRule) {
            // Create version history
            if (!this.ruleHistory.has(rule.id)) {
              this.ruleHistory.set(rule.id, []);
            }
            
            this.ruleHistory.get(rule.id)!.push({
              version: existingRule.version || '1.0',
              releaseDate: existingRule.lastUpdated || new Date(),
              changes: ['Rule updated'],
              breakingChanges: false,
              migrationRequired: false
            });
            
            // Update rule
            this.activeRules.set(rule.id, {
              ...existingRule,
              ...rule,
              lastUpdated: new Date()
            });
            
            this.logger.log(`Updated detection rule: ${rule.id}`);
          }
        }
      }

      // Remove rules
      if (updates.remove) {
        for (const ruleId of updates.remove) {
          this.activeRules.delete(ruleId);
          this.logger.log(`Removed detection rule: ${ruleId}`);
        }
      }

      const endTime = Date.now();
      
      this.logger.log(`Detection rules update completed in ${endTime - startTime}ms`);
      
    } catch (error) {
      this.logger.error('Failed to update detection rules:', error);
      throw error;
    }
  }

  async enableRule(ruleId: string): Promise<void> {
    const rule = this.activeRules.get(ruleId);
    if (rule) {
      rule.enabled = true;
      rule.lastUpdated = new Date();
      this.logger.log(`Enabled detection rule: ${ruleId}`);
    } else {
      throw new Error(`Rule not found: ${ruleId}`);
    }
  }

  async disableRule(ruleId: string): Promise<void> {
    const rule = this.activeRules.get(ruleId);
    if (rule) {
      rule.enabled = false;
      rule.lastUpdated = new Date();
      this.logger.log(`Disabled detection rule: ${ruleId}`);
    } else {
      throw new Error(`Rule not found: ${ruleId}`);
    }
  }

  async getRuleStatistics(): Promise<{
    totalRules: number;
    enabledRules: number;
    disabledRules: number;
    rulesByCategory: { [category: string]: number };
    recentExecutions: { [ruleId: string]: number };
    averageExecutionTime: number;
  }> {
    const allRules = Array.from(this.activeRules.values());
    
    const rulesByCategory = allRules.reduce((categories, rule) => {
      categories[rule.type] = (categories[rule.type] || 0) + 1;
      return categories;
    }, {} as { [category: string]: number });

    const recentExecutions: { [ruleId: string]: number } = {};
    this.ruleExecutions.forEach((executions, ruleId) => {
      const recentExecs = executions.filter(exec => 
        Date.now() - exec.timestamp.getTime() < 24 * 60 * 60 * 1000 // Last 24 hours
      );
      recentExecutions[ruleId] = recentExecs.length;
    });

    return {
      totalRules: allRules.length,
      enabledRules: allRules.filter(rule => rule.enabled).length,
      disabledRules: allRules.filter(rule => !rule.enabled).length,
      rulesByCategory,
      recentExecutions,
      averageExecutionTime: 0 // Would need to track execution times
    };
  }

  async getRulePerformance(ruleId: string): Promise<{
    ruleId: string;
    totalExecutions: number;
    successfulExecutions: number;
    successRate: number;
    averageConfidence: number;
    lastExecution: Date;
    executionTrend: 'improving' | 'stable' | 'declining';
  }> {
    const executions = this.ruleExecutions.get(ruleId) || [];
    
    const totalExecutions = executions.length;
    const successfulExecutions = executions.filter(exec => exec.success).length;
    const successRate = totalExecutions > 0 ? successfulExecutions / totalExecutions : 0;
    
    const confidences = executions.map(exec => exec.result.confidence || 0);
    const averageConfidence = confidences.length > 0 ? 
      confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length : 0;
    
    const lastExecution = executions.length > 0 ? executions[executions.length - 1].timestamp : new Date();
    
    // Calculate trend (simplified)
    const recentExecutions = executions.slice(-10);
    const recentSuccessRate = recentExecutions.length > 0 ? 
      recentExecutions.filter(exec => exec.success).length / recentExecutions.length : 0;
    
    let executionTrend: 'improving' | 'stable' | 'declining' = 'stable';
    if (recentExecutions.length >= 5) {
      const olderExecutions = recentExecutions.slice(0, Math.floor(recentExecutions.length / 2));
      const olderSuccessRate = olderExecutions.length > 0 ? 
        olderExecutions.filter(exec => exec.success).length / olderExecutions.length : 0;
      
      if (recentSuccessRate > olderSuccessRate + 0.1) {
        executionTrend = 'improving';
      } else if (recentSuccessRate < olderSuccessRate - 0.1) {
        executionTrend = 'declining';
      }
    }

    return {
      ruleId,
      totalExecutions,
      successfulExecutions,
      successRate,
      averageConfidence,
      lastExecution,
      executionTrend
    };
  }

  private scheduleMonthlyUpdates(): void {
    // Schedule monthly rule updates
    setInterval(async () => {
      await this.performMonthlyUpdate();
    }, 30 * 24 * 60 * 60 * 1000); // 30 days
  }

  private async performMonthlyUpdate(): Promise<void> {
    this.logger.log('Performing monthly detection rules update');

    try {
      // Check for new regulatory requirements
      const newRequirements = await this.checkRegulatoryUpdates();
      
      // Update rules based on new requirements
      if (newRequirements.length > 0) {
        const newRules = this.generateRulesFromRequirements(newRequirements);
        await this.updateDetectionRules({ add: newRules });
      }

      // Optimize existing rules
      await this.optimizeExistingRules();
      
      // Archive old rule versions
      await this.archiveOldRuleVersions();
      
      this.logger.log('Monthly detection rules update completed');
      
    } catch (error) {
      this.logger.error('Failed to perform monthly update:', error);
    }
  }

  private async checkRegulatoryUpdates(): Promise<any[]> {
    // Check for regulatory updates (simplified implementation)
    return [
      {
        type: 'new_reporting_threshold',
        jurisdiction: 'US',
        description: 'New SAR reporting threshold of $5,000',
        effectiveDate: new Date(),
        impact: 'high'
      },
      {
        type: 'enhanced_kyc_requirements',
        jurisdiction: 'EU',
        description: 'Enhanced KYC requirements for crypto transactions',
        effectiveDate: new Date(),
        impact: 'medium'
      }
    ];
  }

  private generateRulesFromRequirements(requirements: any[]): DetectionRule[] {
    const rules: DetectionRule[] = [];
    
    requirements.forEach(req => {
      const rule = this.createRuleFromRequirement(req);
      if (rule) {
        rules.push(rule);
      }
    });
    
    return rules;
  }

  private createRuleFromRequirement(requirement: any): DetectionRule | null {
    switch (requirement.type) {
      case 'new_reporting_threshold':
        return {
          id: `auto_rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          name: `New Reporting Threshold - ${requirement.jurisdiction}`,
          condition: `transactions.totalAmount > ${requirement.threshold}`,
          threshold: requirement.threshold,
          timeWindow: 86400, // 24 hours
          weight: 0.8,
          enabled: true,
          lastUpdated: new Date()
        };
      
      case 'enhanced_kyc_requirements':
        return {
          id: `auto_rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          name: `Enhanced KYC Requirements - ${requirement.jurisdiction}`,
          condition: 'user.verification_level < enhanced',
          threshold: 1,
          timeWindow: 86400,
          weight: 0.7,
          enabled: true,
          lastUpdated: new Date()
        };
      
      default:
        return null;
    }
  }

  private async optimizeExistingRules(): Promise<void> {
    // Optimize existing rules based on performance
    const allRules = Array.from(this.activeRules.values());
    
    for (const rule of allRules) {
      const performance = await this.getRulePerformance(rule.id);
      
      // Disable underperforming rules
      if (performance.successRate < 0.3 && performance.totalExecutions > 100) {
        await this.disableRule(rule.id);
        this.logger.log(`Disabled underperforming rule: ${rule.id}`);
      }
      
      // Adjust weights based on performance
      if (performance.successRate > 0.8 && performance.totalExecutions > 50) {
        rule.weight = Math.min(1.0, rule.weight * 1.1);
        rule.lastUpdated = new Date();
      }
    }
  }

  private async archiveOldRuleVersions(): Promise<void> {
    // Archive old rule versions (simplified implementation)
    const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days ago
    
    this.ruleHistory.forEach((versions, ruleId) => {
      const recentVersions = versions.filter(version => 
        version.releaseDate > cutoffDate
      );
      
      if (recentVersions.length !== versions.length) {
        this.ruleHistory.set(ruleId, recentVersions);
      }
    });
  }

  private initializeDetectionRules(): void {
    // Initialize default detection rules
    const defaultRules = [
      {
        id: 'privacy_tool_detection',
        name: 'Privacy Tool Detection',
        condition: 'privacy_tools.enabled == true',
        threshold: 1,
        timeWindow: 3600,
        weight: 0.7,
        enabled: true,
        lastUpdated: new Date()
      },
      {
        id: 'vpn_detection',
        name: 'VPN Detection',
        condition: 'network.vpn == true',
        threshold: 1,
        timeWindow: 3600,
        weight: 0.8,
        enabled: true,
        lastUpdated: new Date()
      },
      {
        id: 'high_transaction_volume',
        name: 'High Transaction Volume',
        condition: 'transactions.totalAmount > 10000',
        threshold: 10000,
        timeWindow: 86400,
        weight: 0.6,
        enabled: true,
        lastUpdated: new Date()
      },
      {
        id: 'multiple_jurisdictions',
        name: 'Multiple Jurisdictions',
        condition: 'jurisdiction_changes > 2',
        threshold: 2,
        timeWindow: 86400,
        weight: 0.7,
        enabled: true,
        lastUpdated: new Date()
      },
      {
        id: 'rapid_transactions',
        name: 'Rapid Transactions',
        condition: 'transactions.count > 10',
        threshold: 10,
        timeWindow: 3600,
        weight: 0.6,
        enabled: true,
        lastUpdated: new Date()
      },
      {
        id: 'high_risk_jurisdiction',
        name: 'High Risk Jurisdiction',
        condition: 'jurisdiction.riskLevel == "high"',
        threshold: 1,
        timeWindow: 86400,
        weight: 0.8,
        enabled: true,
        lastUpdated: new Date()
      }
    ];

    defaultRules.forEach(rule => {
      this.activeRules.set(rule.id, rule);
    });

    this.logger.log(`Initialized ${defaultRules.length} default detection rules`);
  }

  async getActiveRules(): Promise<DetectionRule[]> {
    return Array.from(this.activeRules.values());
  }

  async getRuleHistory(ruleId: string): Promise<Version[]> {
    return this.ruleHistory.get(ruleId) || [];
  }

  async getDetectionRulesEngine(): Promise<{
    rules: DetectionRules;
    statistics: any;
    lastUpdate: Date;
  }> {
    const rules: DetectionRules = {
      id: 'main',
      name: 'Regulatory Arbitrage Detection Rules',
      version: '1.0',
      rules: Array.from(this.activeRules.values()),
      versionHistory: Array.from(this.ruleHistory.entries()).map(([ruleId, versions]) => ({
        ruleId,
        versions
      })),
      lastUpdated: new Date(),
      updateFrequency: 'monthly',
      autoUpdate: true
    };

    const statistics = await this.getRuleStatistics();

    return {
      rules,
      statistics,
      lastUpdate: new Date()
    };
  }
}
