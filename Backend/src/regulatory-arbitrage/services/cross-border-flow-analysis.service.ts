import { Injectable, Logger } from '@nestjs/common';
import {
  CrossBorderFlow,
  TransactionType,
  FlowPurpose,
  FlowRoute,
  FlowTiming,
  Intermediary,
  SuspiciousIndicator,
  SuspiciousIndicatorType,
  RiskLevel,
  JurisdictionProfile,
  ArbitrageDetection,
  ArbitrageType,
  FlowAnalysis
} from '../interfaces/regulatory-arbitrage.interface';

@Injectable()
export class CrossBorderFlowAnalysisService {
  private readonly logger = new Logger(CrossBorderFlowAnalysisService.name);
  private readonly flowDatabase = new Map<string, CrossBorderFlow[]>();
  private readonly jurisdictionDatabase = new Map<string, JurisdictionProfile>();
  private readonly suspiciousRoutes = new Map<string, FlowRoute>();
  private readonly highRiskIntermediaries = new Map<string, Intermediary>();

  constructor() {
    this.initializeJurisdictionDatabase();
    this.initializeSuspiciousRoutes();
    this.initializeHighRiskIntermediaries();
  }

  async analyzeCrossBorderFlows(
    userId: string,
    transactions: any[]
  ): Promise<{
    arbitrageDetections: ArbitrageDetection[];
    suspiciousFlows: CrossBorderFlow[];
    riskScore: number;
    analysis: FlowAnalysis;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Analyzing cross-border flows for user ${userId}`);

    try {
      // Extract cross-border flows from transactions
      const crossBorderFlows = await this.extractCrossBorderFlows(userId, transactions);
      
      // Store flows for analysis
      this.flowDatabase.set(userId, crossBorderFlows);
      
      // Analyze each flow
      const flowAnalyses = await Promise.all(
        crossBorderFlows.map(flow => this.analyzeFlow(flow))
      );
      
      // Detect regulatory arbitrage
      const arbitrageDetections = await this.detectRegulatoryArbitrage(
        crossBorderFlows,
        flowAnalyses
      );
      
      // Identify suspicious flows
      const suspiciousFlows = crossBorderFlows.filter(flow => 
        flow.riskScore > 70 || flow.suspiciousIndicators.length > 0
      );
      
      // Calculate overall risk score
      const overallRiskScore = this.calculateOverallRiskScore(
        crossBorderFlows,
        arbitrageDetections
      );
      
      // Generate comprehensive analysis
      const analysis: FlowAnalysis = {
        totalFlows: crossBorderFlows.length,
        crossBorderTransactions: crossBorderFlows.length,
        uniqueJurisdictions: this.getUniqueJurisdictions(crossBorderFlows),
        averageRiskScore: crossBorderFlows.reduce((sum, flow) => sum + flow.riskScore, 0) / crossBorderFlows.length,
        arbitrageOpportunities: arbitrageDetections.length,
        suspiciousIndicators: this.aggregateSuspiciousIndicators(crossBorderFlows),
        riskDistribution: this.calculateRiskDistribution(crossBorderFlows),
        jurisdictionPatterns: this.analyzeJurisdictionPatterns(crossBorderFlows),
        timingPatterns: this.analyzeTimingPatterns(crossBorderFlows),
        intermediaries: this.analyzeIntermediaries(crossBorderFlows)
      };

      const endTime = Date.now();
      
      this.logger.log(`Cross-border flow analysis completed for user ${userId} in ${endTime - startTime}ms`);
      
      return {
        arbitrageDetections,
        suspiciousFlows,
        riskScore: overallRiskScore,
        analysis
      };
      
    } catch (error) {
      this.logger.error(`Failed to analyze cross-border flows for user ${userId}:`, error);
      throw error;
    }
  }

  private async extractCrossBorderFlows(
    userId: string,
    transactions: any[]
  ): Promise<CrossBorderFlow[]> {
    const crossBorderFlows: CrossBorderFlow[] = [];
    
    // Group transactions by potential flows
    const transactionGroups = this.groupTransactionsByFlow(transactions);
    
    for (const group of transactionGroups) {
      // Determine if this is a cross-border flow
      if (this.isCrossBorderFlow(group)) {
        const flow = await this.createCrossBorderFlow(userId, group);
        crossBorderFlows.push(flow);
      }
    }
    
    return crossBorderFlows;
  }

  private async analyzeFlow(flow: CrossBorderFlow): Promise<any> {
    const analysis = {
      routeAnalysis: await this.analyzeFlowRoute(flow),
      timingAnalysis: await this.analyzeFlowTiming(flow),
      purposeAnalysis: await this.analyzeFlowPurpose(flow),
      intermediaryAnalysis: await this.analyzeFlowIntermediaries(flow),
      riskAnalysis: await this.analyzeFlowRisk(flow)
    };
    
    // Update flow with analysis results
    flow.riskScore = analysis.riskAnalysis.riskScore;
    flow.suspiciousIndicators = analysis.riskAnalysis.suspiciousIndicators;
    
    return analysis;
  }

  private async detectRegulatoryArbitrage(
    flows: CrossBorderFlow[],
    analyses: any[]
  ): Promise<ArbitrageDetection[]> {
    const arbitrageDetections: ArbitrageDetection[] = [];
    
    // Detect jurisdiction shopping
    const jurisdictionShopping = await this.detectJurisdictionShopping(flows);
    if (jurisdictionShopping.length > 0) {
      arbitrageDetections.push(...jurisdictionShopping);
    }
    
    // Detect treaty shopping
    const treatyShopping = await this.detectTreatyShopping(flows);
    if (treatyShopping.length > 0) {
      arbitrageDetections.push(...treatyShopping);
    }
    
    // Detect regulatory arbitrage patterns
    const regulatoryArbitrage = await this.detectRegulatoryArbitragePatterns(flows);
    if (regulatoryArbitrage.length > 0) {
      arbitrageDetections.push(...regulatoryArbitrage);
    }
    
    // Detect tax arbitrage
    const taxArbitrage = await this.detectTaxArbitrage(flows);
    if (taxArbitrage.length > 0) {
      arbitrageDetections.push(...taxArbitrage);
    }
    
    return arbitrageDetections;
  }

  private async detectJurisdictionShopping(flows: CrossBorderFlow[]): Promise<ArbitrageDetection[]> {
    const detections: ArbitrageDetection[] = [];
    
    // Group flows by purpose
    const flowsByPurpose = this.groupFlowsByPurpose(flows);
    
    for (const [purpose, purposeFlows] of flowsByPurpose) {
      // Check if user is using multiple jurisdictions for similar transactions
      const jurisdictions = this.getUniqueJurisdictions(purposeFlows);
      
      if (jurisdictions.length > 2) {
        // Analyze regulatory differences
        const regulatoryDifferences = await this.analyzeRegulatoryDifferences(jurisdictions);
        
        if (regulatoryDifferences.hasSignificantDifferences) {
          detections.push({
            id: `jurisdiction_shopping_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            userId: purposeFlows[0].userId,
            type: ArbitrageType.JURISDICTIONAL,
            jurisdictions: jurisdictions,
            transactions: purposeFlows.map(f => f.id),
            amount: purposeFlows.reduce((sum, f) => sum + f.amount, 0),
            currency: purposeFlows[0].currency,
            profit: this.calculateArbitrageProfit(regulatoryDifferences),
            riskScore: 85,
            evidence: {
              purpose,
              jurisdictions,
              regulatoryDifferences,
              flows: purposeFlows
            },
            detected: new Date()
          });
        }
      }
    }
    
    return detections;
  }

  private async detectTreatyShopping(flows: CrossBorderFlow[]): Promise<ArbitrageDetection[]> {
    const detections: ArbitrageDetection[] = [];
    
    // Look for flows that exploit treaty benefits
    for (const flow of flows) {
      const treatyBenefits = await this.analyzeTreatyBenefits(flow);
      
      if (treatyBenefits.hasExploitableBenefits) {
        detections.push({
          id: `treaty_shopping_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          userId: flow.userId,
          type: ArbitrageType.REGULATORY,
          jurisdictions: [flow.sourceJurisdiction, flow.targetJurisdiction],
          transactions: [flow.id],
          amount: flow.amount,
          currency: flow.currency,
          profit: treatyBenefits.estimatedBenefit,
          riskScore: 75,
          evidence: {
            flow,
            treatyBenefits,
            exploitedTreaties: treatyBenefits.exploitedTreaties
          },
          detected: new Date()
        });
      }
    }
    
    return detections;
  }

  private async detectRegulatoryArbitragePatterns(flows: CrossBorderFlow[]): Promise<ArbitrageDetection[]> {
    const detections: ArbitrageDetection[] = [];
    
    // Look for patterns that exploit regulatory differences
    const patterns = await this.identifyRegulatoryArbitragePatterns(flows);
    
    for (const pattern of patterns) {
      if (pattern.confidence > 0.7) {
        detections.push({
          id: `regulatory_arbitrage_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          userId: pattern.flows[0].userId,
          type: ArbitrageType.REGULATORY,
          jurisdictions: pattern.jurisdictions,
          transactions: pattern.flows.map(f => f.id),
          amount: pattern.flows.reduce((sum, f) => sum + f.amount, 0),
          currency: pattern.flows[0].currency,
          profit: pattern.estimatedProfit,
          riskScore: 80,
          evidence: {
            pattern,
            regulatoryDifferences: pattern.regulatoryDifferences,
            flows: pattern.flows
          },
          detected: new Date()
        });
      }
    }
    
    return detections;
  }

  private async detectTaxArbitrage(flows: CrossBorderFlow[]): Promise<ArbitrageDetection[]> {
    const detections: ArbitrageDetection[] = [];
    
    // Look for tax arbitrage opportunities
    const taxArbitrageOpportunities = await this.identifyTaxArbitrageOpportunities(flows);
    
    for (const opportunity of taxArbitrageOpportunities) {
      if (opportunity.taxBenefit > 1000) { // Minimum benefit threshold
        detections.push({
          id: `tax_arbitrage_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          userId: opportunity.flows[0].userId,
          type: ArbitrageType.TAX,
          jurisdictions: opportunity.jurisdictions,
          transactions: opportunity.flows.map(f => f.id),
          amount: opportunity.flows.reduce((sum, f) => sum + f.amount, 0),
          currency: opportunity.flows[0].currency,
          profit: opportunity.taxBenefit,
          riskScore: 70,
          evidence: {
            opportunity,
            taxDifferences: opportunity.taxDifferences,
            flows: opportunity.flows
          },
          detected: new Date()
        });
      }
    }
    
    return detections;
  }

  private groupTransactionsByFlow(transactions: any[]): any[][] {
    // Group transactions that are part of the same flow
    const flows = [];
    const processed = new Set<string>();
    
    for (const transaction of transactions) {
      if (!processed.has(transaction.id)) {
        const flow = this.identifyTransactionFlow(transaction, transactions);
        flows.push(flow.transactions);
        flow.transactions.forEach(t => processed.add(t.id));
      }
    }
    
    return flows;
  }

  private identifyTransactionFlow(transaction: any, allTransactions: any[]): any {
    // Identify related transactions that form a flow
    const relatedTransactions = [transaction];
    
    // Look for transactions with similar characteristics
    for (const otherTx of allTransactions) {
      if (otherTx.id !== transaction.id && this.areTransactionsRelated(transaction, otherTx)) {
        relatedTransactions.push(otherTx);
      }
    }
    
    return {
      transactions: relatedTransactions.sort((a, b) => a.timestamp - b.timestamp)
    };
  }

  private areTransactionsRelated(tx1: any, tx2: any): boolean {
    // Check if transactions are related based on various factors
    const timeThreshold = 3600000; // 1 hour in milliseconds
    const timeDiff = Math.abs(tx1.timestamp - tx2.timestamp);
    
    // Related if within time threshold and has other similarities
    if (timeDiff > timeThreshold) return false;
    
    // Check for amount relationships
    if (Math.abs(tx1.amount - tx2.amount) < (tx1.amount * 0.1)) return true;
    
    // Check for destination relationships
    if (tx1.destination === tx2.destination) return true;
    
    // Check for intermediary relationships
    if (tx1.intermediary === tx2.intermediary) return true;
    
    return false;
  }

  private isCrossBorderFlow(transactions: any[]): boolean {
    // Check if transactions involve multiple jurisdictions
    const jurisdictions = new Set();
    
    for (const tx of transactions) {
      if (tx.sourceJurisdiction) jurisdictions.add(tx.sourceJurisdiction);
      if (tx.targetJurisdiction) jurisdictions.add(tx.targetJurisdiction);
      if (tx.intermediaryJurisdiction) jurisdictions.add(tx.intermediaryJurisdiction);
    }
    
    return jurisdictions.size > 1;
  }

  private async createCrossBorderFlow(userId: string, transactions: any[]): Promise<CrossBorderFlow> {
    const firstTx = transactions[0];
    const lastTx = transactions[transactions.length - 1];
    
    // Determine source and target jurisdictions
    const sourceJurisdiction = this.determineSourceJurisdiction(transactions);
    const targetJurisdiction = this.determineTargetJurisdiction(transactions);
    
    // Create flow route
    const route = await this.createFlowRoute(transactions);
    
    // Analyze timing
    const timing = {
      startTime: new Date(firstTx.timestamp),
      endTime: new Date(lastTx.timestamp),
      duration: lastTx.timestamp - firstTx.timestamp,
      frequency: this.calculateFlowFrequency(transactions),
      regularity: this.calculateFlowRegularity(transactions),
      unusualPatterns: await this.detectUnusualTimingPatterns(transactions)
    };
    
    // Determine purpose
    const purpose = this.inferFlowPurpose(transactions);
    
    // Identify intermediaries
    const intermediaries = await this.identifyIntermediaries(transactions);
    
    // Calculate risk score
    const riskScore = await this.calculateFlowRiskScore({
      sourceJurisdiction,
      targetJurisdiction,
      route,
      timing,
      purpose,
      intermediaries,
      transactions
    });
    
    // Identify suspicious indicators
    const suspiciousIndicators = await this.identifySuspiciousIndicators({
      sourceJurisdiction,
      targetJurisdiction,
      route,
      timing,
      purpose,
      intermediaries,
      transactions
    });

    return {
      id: `flow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      sourceJurisdiction,
      targetJurisdiction,
      transactionType: this.determineTransactionType(transactions),
      amount: transactions.reduce((sum, tx) => sum + tx.amount, 0),
      currency: firstTx.currency,
      route,
      timing,
      purpose,
      intermediaries,
      riskScore,
      suspiciousIndicators,
      detected: new Date()
    };
  }

  private determineSourceJurisdiction(transactions: any[]): string {
    // Determine the most likely source jurisdiction
    const jurisdictions = transactions
      .map(tx => tx.sourceJurisdiction)
      .filter(jurisdiction => jurisdiction);
    
    if (jurisdictions.length === 0) return 'Unknown';
    
    // Return the most common jurisdiction
    const jurisdictionCounts = jurisdictions.reduce((counts, jurisdiction) => {
      counts[jurisdiction] = (counts[jurisdiction] || 0) + 1;
      return counts;
    }, {});
    
    return Object.keys(jurisdictionCounts).reduce((a, b) => 
      jurisdictionCounts[a] > jurisdictionCounts[b] ? a : b
    );
  }

  private determineTargetJurisdiction(transactions: any[]): string {
    // Determine the most likely target jurisdiction
    const jurisdictions = transactions
      .map(tx => tx.targetJurisdiction)
      .filter(jurisdiction => jurisdiction);
    
    if (jurisdictions.length === 0) return 'Unknown';
    
    // Return the most common jurisdiction
    const jurisdictionCounts = jurisdictions.reduce((counts, jurisdiction) => {
      counts[jurisdiction] = (counts[jurisdiction] || 0) + 1;
      return counts;
    }, {});
    
    return Object.keys(jurisdictionCounts).reduce((a, b) => 
      jurisdictionCounts[a] > jurisdictionCounts[b] ? a : b
    );
  }

  private async createFlowRoute(transactions: any[]): Promise<FlowRoute> {
    const path = transactions.map(tx => tx.destination);
    const intermediaries = await this.identifyIntermediaries(transactions);
    const methods = [...new Set(transactions.map(tx => tx.method))];
    const currencies = [...new Set(transactions.map(tx => tx.currency))];
    
    return {
      path,
      intermediaries: intermediaries.map(i => i.id),
      methods,
      currencies,
      estimatedTime: this.estimateFlowTime(transactions),
      cost: transactions.reduce((sum, tx) => sum + (tx.fee || 0), 0),
      riskLevel: this.calculateRouteRisk(path, intermediaries)
    };
  }

  private inferFlowPurpose(transactions: any[]): FlowPurpose {
    // Analyze transaction patterns to infer purpose
    const patterns = this.analyzeTransactionPatterns(transactions);
    
    // Use heuristics to determine purpose
    if (patterns.hasInvestmentCharacteristics) {
      return FlowPurpose.INVESTMENT;
    } else if (patterns.hasSpeculationCharacteristics) {
      return FlowPurpose.SPECULATION;
    } else if (patterns.hasArbitrageCharacteristics) {
      return FlowPurpose.ARBITRAGE;
    } else if (patterns.hasTaxEvasionCharacteristics) {
      return FlowPurpose.TAX_EVASION;
    } else if (patterns.hasMoneyLaunderingCharacteristics) {
      return FlowPurpose.MONEY_LAUNDERING;
    } else {
      return FlowPurpose.PERSONAL_USE;
    }
  }

  private async identifyIntermediaries(transactions: any[]): Promise<Intermediary[]> {
    const intermediaries: Intermediary[] = [];
    const processed = new Set<string>();
    
    for (const tx of transactions) {
      if (tx.intermediary && !processed.has(tx.intermediary.id)) {
        const intermediary = await this.createIntermediary(tx.intermediary);
        intermediaries.push(intermediary);
        processed.add(tx.intermediary.id);
      }
    }
    
    return intermediaries;
  }

  private async createIntermediary(intermediaryData: any): Promise<Intermediary> {
    // Check if it's a known high-risk intermediary
    const knownHighRisk = this.highRiskIntermediaries.get(intermediaryData.id);
    
    if (knownHighRisk) {
      return knownHighRisk;
    }
    
    // Analyze intermediary risk
    const riskLevel = await this.assessIntermediaryRisk(intermediaryData);
    
    return {
      id: intermediaryData.id,
      name: intermediaryData.name || 'Unknown',
      type: this.determineIntermediaryType(intermediaryData),
      jurisdiction: intermediaryData.jurisdiction || 'Unknown',
      riskLevel,
      suspicious: riskLevel === RiskLevel.HIGH || riskLevel === RiskLevel.CRITICAL,
      details: intermediaryData
    };
  }

  private determineIntermediaryType(intermediaryData: any): any {
    // Determine the type of intermediary
    if (intermediaryData.type === 'exchange') return 'EXCHANGE';
    if (intermediaryData.type === 'wallet') return 'WALLET';
    if (intermediaryData.type === 'mixer') return 'MIXER';
    if (intermediaryData.type === 'tumbler') return 'TUMBLER';
    if (intermediaryData.type === 'payment_processor') return 'PAYMENT_PROCESSOR';
    if (intermediaryData.type === 'bank') return 'BANK';
    if (intermediaryData.type === 'crypto_atm') return 'CRYPTO_ATM';
    if (intermediaryData.type === 'p2p_platform') return 'P2P_PLATFORM';
    
    return 'UNKNOWN';
  }

  private async assessIntermediaryRisk(intermediaryData: any): Promise<RiskLevel> {
    // Assess risk based on various factors
    let riskScore = 0;
    
    // Check if it's a known high-risk type
    const highRiskTypes = ['MIXER', 'TUMBLER', 'CRYPTO_ATM'];
    if (highRiskTypes.includes(this.determineIntermediaryType(intermediaryData))) {
      riskScore += 50;
    }
    
    // Check jurisdiction risk
    const jurisdiction = this.jurisdictionDatabase.get(intermediaryData.jurisdiction);
    if (jurisdiction) {
      switch (jurisdiction.riskLevel) {
        case RiskLevel.HIGH:
          riskScore += 30;
          break;
        case RiskLevel.CRITICAL:
          riskScore += 50;
          break;
      }
    }
    
    // Check for suspicious patterns
    if (intermediaryData.suspicious) {
      riskScore += 40;
    }
    
    if (riskScore >= 80) return RiskLevel.CRITICAL;
    if (riskScore >= 60) return RiskLevel.HIGH;
    if (riskScore >= 40) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private async calculateFlowRiskScore(flowData: any): Promise<number> {
    let riskScore = 0;
    
    // Risk from jurisdiction differences
    const sourceJur = this.jurisdictionDatabase.get(flowData.sourceJurisdiction);
    const targetJur = this.jurisdictionDatabase.get(flowData.targetJurisdiction);
    
    if (sourceJur && targetJur) {
      const regDiff = this.calculateRegulatoryDifference(sourceJur, targetJur);
      riskScore += regDiff.riskScore;
    }
    
    // Risk from route
    riskScore += flowData.route.riskLevel === RiskLevel.HIGH ? 30 : 
                 flowData.route.riskLevel === RiskLevel.MEDIUM ? 15 : 0;
    
    // Risk from timing
    if (flowData.timing.unusualPatterns.length > 0) {
      riskScore += flowData.timing.unusualPatterns.length * 10;
    }
    
    // Risk from intermediaries
    const highRiskIntermediaries = flowData.intermediaries.filter(i => 
      i.riskLevel === RiskLevel.HIGH || i.riskLevel === RiskLevel.CRITICAL
    );
    riskScore += highRiskIntermediaries.length * 20;
    
    // Risk from purpose
    if (flowData.purpose === FlowPurpose.TAX_EVASION) riskScore += 40;
    if (flowData.purpose === FlowPurpose.MONEY_LAUNDERING) riskScore += 50;
    if (flowData.purpose === FlowPurpose.REGULATORY_ARBITRAGE) riskScore += 35;
    
    return Math.min(100, riskScore);
  }

  private async identifySuspiciousIndicators(flowData: any): Promise<SuspiciousIndicator[]> {
    const indicators: SuspiciousIndicator[] = [];
    
    // Check for round-tripping
    if (this.isRoundTripping(flowData.transactions)) {
      indicators.push({
        type: SuspiciousIndicatorType.ROUND_TRIPPING,
        description: 'Round-tripping transaction pattern detected',
        severity: RiskLevel.HIGH,
        confidence: 0.8,
        evidence: { transactions: flowData.transactions },
        detected: new Date()
      });
    }
    
    // Check for structuring
    if (this.isStructuring(flowData.transactions)) {
      indicators.push({
        type: SuspiciousIndicatorType.STRUCTURING,
        description: 'Transaction structuring detected',
        severity: RiskLevel.HIGH,
        confidence: 0.7,
        evidence: { transactions: flowData.transactions },
        detected: new Date()
      });
    }
    
    // Check for shell company usage
    if (this.hasShellCompanyIndicators(flowData.intermediaries)) {
      indicators.push({
        type: SuspiciousIndicatorType.SHELL_COMPANY_USAGE,
        description: 'Shell company usage detected',
        severity: RiskLevel.MEDIUM,
        confidence: 0.6,
        evidence: { intermediaries: flowData.intermediaries },
        detected: new Date()
      });
    }
    
    // Check for privacy tool usage
    if (this.hasPrivacyToolIndicators(flowData.route)) {
      indicators.push({
        type: SuspiciousIndicatorType.PRIVACY_TOOL_USAGE,
        description: 'Privacy tool usage detected',
        severity: RiskLevel.MEDIUM,
        confidence: 0.7,
        evidence: { route: flowData.route },
        detected: new Date()
      });
    }
    
    return indicators;
  }

  // Helper methods
  private isRoundTripping(transactions: any[]): boolean {
    if (transactions.length < 2) return false;
    
    // Check if funds return to origin
    const firstTx = transactions[0];
    const lastTx = transactions[transactions.length - 1];
    
    return firstTx.source === lastTx.destination;
  }

  private isStructuring(transactions: any[]): boolean {
    if (transactions.length < 3) return false;
    
    // Check for amounts just below reporting thresholds
    const amounts = transactions.map(tx => tx.amount);
    const reportingThreshold = 10000; // Example threshold
    
    const belowThreshold = amounts.filter(amount => 
      amount < reportingThreshold && amount > reportingThreshold * 0.9
    );
    
    return belowThreshold.length >= 2;
  }

  private hasShellCompanyIndicators(intermediaries: Intermediary[]): boolean {
    // Check for shell company indicators
    return intermediaries.some(intermediary => 
      intermediary.type === 'UNKNOWN' || 
      intermediary.suspicious ||
      intermediary.riskLevel === RiskLevel.HIGH
    );
  }

  private hasPrivacyToolIndicators(route: FlowRoute): boolean {
    // Check for privacy tool indicators in route
    return route.methods.some(method => 
      method.toLowerCase().includes('mixer') ||
      method.toLowerCase().includes('tumbler') ||
      method.toLowerCase().includes('privacy')
    );
  }

  private calculateOverallRiskScore(flows: CrossBorderFlow[], detections: ArbitrageDetection[]): number {
    let totalScore = 0;
    
    // Score from flows
    const averageFlowRisk = flows.reduce((sum, flow) => sum + flow.riskScore, 0) / flows.length;
    totalScore += averageFlowRisk * 0.6;
    
    // Score from arbitrage detections
    const arbitrageScore = detections.length * 25;
    totalScore += arbitrageScore * 0.4;
    
    return Math.min(100, totalScore);
  }

  private getUniqueJurisdictions(flows: CrossBorderFlow[]): string[] {
    const jurisdictions = new Set<string>();
    
    flows.forEach(flow => {
      jurisdictions.add(flow.sourceJurisdiction);
      jurisdictions.add(flow.targetJurisdiction);
      flow.intermediaries.forEach(intermediary => {
        jurisdictions.add(intermediary.jurisdiction);
      });
    });
    
    return Array.from(jurisdictions);
  }

  private aggregateSuspiciousIndicators(flows: CrossBorderFlow[]): SuspiciousIndicator[] {
    const allIndicators = flows.flatMap(flow => flow.suspiciousIndicators);
    
    // Remove duplicates and sort by severity
    const uniqueIndicators = allIndicators.filter((indicator, index, self) =>
      self.findIndex(i => i.type === indicator.type) === index
    );
    
    return uniqueIndicators.sort((a, b) => {
      const severityOrder = { [RiskLevel.LOW]: 1, [RiskLevel.MEDIUM]: 2, [RiskLevel.HIGH]: 3, [RiskLevel.CRITICAL]: 4 };
      return severityOrder[b.severity] - severityOrder[a.severity];
    });
  }

  private calculateRiskDistribution(flows: CrossBorderFlow[]): any {
    const distribution = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };
    
    flows.forEach(flow => {
      if (flow.riskScore < 25) distribution.low++;
      else if (flow.riskScore < 50) distribution.medium++;
      else if (flow.riskScore < 75) distribution.high++;
      else distribution.critical++;
    });
    
    return distribution;
  }

  private analyzeJurisdictionPatterns(flows: CrossBorderFlow[]): any {
    const patterns = {
      frequentPairs: {},
      regulatoryArbitrageRoutes: [],
      highRiskCorridors: []
    };
    
    // Analyze frequent jurisdiction pairs
    flows.forEach(flow => {
      const pair = `${flow.sourceJurisdiction}-${flow.targetJurisdiction}`;
      patterns.frequentPairs[pair] = (patterns.frequentPairs[pair] || 0) + 1;
    });
    
    // Identify regulatory arbitrage routes
    patterns.regulatoryArbitrageRoutes = flows.filter(flow => 
      flow.purpose === FlowPurpose.REGULATORY_ARBITRAGE
    ).map(flow => `${flow.sourceJurisdiction}-${flow.targetJurisdiction}`);
    
    // Identify high-risk corridors
    patterns.highRiskCorridors = flows.filter(flow => 
      flow.riskScore > 70
    ).map(flow => `${flow.sourceJurisdiction}-${flow.targetJurisdiction}`);
    
    return patterns;
  }

  private analyzeTimingPatterns(flows: CrossBorderFlow[]): any {
    const patterns = {
      peakHours: [],
      unusualTiming: [],
      coordinatedPatterns: []
    };
    
    // Analyze timing patterns
    flows.forEach(flow => {
      if (flow.timing.unusualPatterns.length > 0) {
        patterns.unusualTiming.push({
          flowId: flow.id,
          patterns: flow.timing.unusualPatterns
        });
      }
    });
    
    return patterns;
  }

  private analyzeIntermediaries(flows: CrossBorderFlow[]): any {
    const intermediaries = new Map();
    
    flows.forEach(flow => {
      flow.intermediaries.forEach(intermediary => {
        if (!intermediaries.has(intermediary.id)) {
          intermediaries.set(intermediary.id, {
            ...intermediary,
            usageCount: 0,
            totalVolume: 0
          });
        }
        
        const data = intermediaries.get(intermediary.id);
        data.usageCount++;
        data.totalVolume += flow.amount;
      });
    });
    
    return Array.from(intermediaries.values());
  }

  // Additional helper methods (simplified implementations)
  private initializeJurisdictionDatabase(): void {
    // Initialize with sample jurisdictions
    this.jurisdictionDatabase.set('US', {
      id: 'us',
      name: 'United States',
      isoCode: 'US',
      region: 'North America',
      regulatoryFramework: 'complex',
      taxJurisdiction: true,
      financialRegulations: {} as any,
      privacyLaws: {} as any,
      reportingRequirements: {} as any,
      enforcementActions: {} as any,
      riskLevel: RiskLevel.MEDIUM,
      lastUpdated: new Date()
    });
    
    // Add more jurisdictions...
  }

  private initializeSuspiciousRoutes(): void {
    // Initialize with known suspicious routes
    this.suspiciousRoutes.set('US-CR', {
      path: ['US', 'CR'],
      intermediaries: ['exchange_1', 'mixer_1'],
      methods: ['transfer', 'mix'],
      currencies: ['USD', 'BTC'],
      estimatedTime: 3600,
      cost: 50,
      riskLevel: RiskLevel.HIGH
    });
    
    // Add more routes...
  }

  private initializeHighRiskIntermediaries(): void {
    // Initialize with known high-risk intermediaries
    this.highRiskIntermediaries.set('mixer_1', {
      id: 'mixer_1',
      name: 'High Risk Mixer',
      type: 'MIXER',
      jurisdiction: 'Unknown',
      riskLevel: RiskLevel.HIGH,
      suspicious: true,
      details: { type: 'mixer', risk: 'high' }
    });
    
    // Add more intermediaries...
  }

  private groupFlowsByPurpose(flows: CrossBorderFlow[]): Map<FlowPurpose, CrossBorderFlow[]> {
    const grouped = new Map<FlowPurpose, CrossBorderFlow[]>();
    
    flows.forEach(flow => {
      if (!grouped.has(flow.purpose)) {
        grouped.set(flow.purpose, []);
      }
      grouped.get(flow.purpose)!.push(flow);
    });
    
    return grouped;
  }

  private getUniqueJurisdictions(flows: CrossBorderFlow[]): string[] {
    const jurisdictions = new Set<string>();
    
    flows.forEach(flow => {
      jurisdictions.add(flow.sourceJurisdiction);
      jurisdictions.add(flow.targetJurisdiction);
    });
    
    return Array.from(jurisdictions);
  }

  private async analyzeRegulatoryDifferences(jurisdictions: string[]): Promise<any> {
    // Analyze regulatory differences between jurisdictions
    const regulations = jurisdictions.map(jur => 
      this.jurisdictionDatabase.get(jur)
    ).filter(jur => jur);
    
    if (regulations.length < 2) {
      return { hasSignificantDifferences: false, differences: [] };
    }
    
    const differences = [];
    
    // Compare KYC requirements
    for (let i = 0; i < regulations.length - 1; i++) {
      for (let j = i + 1; j < regulations.length; j++) {
        const kycDiff = this.compareKYCRequirements(regulations[i], regulations[j]);
        if (kycDiff.hasDifference) {
          differences.push(kycDiff);
        }
      }
    }
    
    return {
      hasSignificantDifferences: differences.length > 0,
      differences,
      riskScore: differences.length * 10
    };
  }

  private compareKYCRequirements(reg1: any, reg2: any): any {
    // Compare KYC requirements between regulations
    const kyc1 = reg1.financialRegulations?.kycRequirements;
    const kyc2 = reg2.financialRegulations?.kycRequirements;
    
    if (!kyc1 || !kyc2) {
      return { hasDifference: false };
    }
    
    const differences = [];
    
    if (kyc1.identityVerification !== kyc2.identityVerification) {
      differences.push('identityVerification');
    }
    
    if (kyc1.sourceOfFunds !== kyc2.sourceOfFunds) {
      differences.push('sourceOfFunds');
    }
    
    return {
      hasDifference: differences.length > 0,
      differences,
      riskScore: differences.length * 5
    };
  }

  private calculateArbitrageProfit(regulatoryDifferences: any): number {
    // Estimate potential profit from regulatory arbitrage
    return regulatoryDifferences.riskScore * 100; // Simplified calculation
  }

  private determineTransactionType(transactions: any[]): TransactionType {
    // Determine the primary transaction type
    const types = transactions.map(tx => tx.type);
    const typeCounts = types.reduce((counts, type) => {
      counts[type] = (counts[type] || 0) + 1;
      return counts;
    }, {});
    
    return Object.keys(typeCounts).reduce((a, b) => 
      typeCounts[a] > typeCounts[b] ? a : b
    ) as TransactionType;
  }

  private calculateFlowFrequency(transactions: any[]): number {
    if (transactions.length < 2) return 0;
    
    const firstTx = transactions[0];
    const lastTx = transactions[transactions.length - 1];
    const timeSpan = lastTx.timestamp - firstTx.timestamp;
    
    return transactions.length / (timeSpan / (24 * 60 * 60 * 1000)); // flows per day
  }

  private calculateFlowRegularity(transactions: any[]): string {
    // Analyze the regularity of the flow
    const intervals = [];
    
    for (let i = 1; i < transactions.length; i++) {
      intervals.push(transactions[i].timestamp - transactions[i-1].timestamp);
    }
    
    if (intervals.length === 0) return 'unknown';
    
    const avgInterval = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
    const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
    
    if (variance < avgInterval * 0.1) return 'regular';
    if (variance < avgInterval * 0.3) return 'semi_regular';
    return 'irregular';
  }

  private async detectUnusualTimingPatterns(transactions: any[]): Promise<any[]> {
    // Detect unusual timing patterns
    const patterns = [];
    
    // Check for transactions at unusual hours
    const unusualHours = transactions.filter(tx => {
      const hour = new Date(tx.timestamp).getHours();
      return hour < 6 || hour > 22; // Unusual hours
    });
    
    if (unusualHours.length > 0) {
      patterns.push({
        type: 'unusual_hours',
        description: `Transactions at unusual hours: ${unusualHours.length}`,
        severity: RiskLevel.MEDIUM
      });
    }
    
    return patterns;
  }

  private estimateFlowTime(transactions: any[]): number {
    // Estimate flow completion time
    if (transactions.length === 0) return 0;
    
    const firstTx = transactions[0];
    const lastTx = transactions[transactions.length - 1];
    
    return lastTx.timestamp - firstTx.timestamp;
  }

  private calculateRouteRisk(path: string[], intermediaries: Intermediary[]): RiskLevel {
    let riskScore = 0;
    
    // Risk from path length
    riskScore += path.length * 5;
    
    // Risk from intermediaries
    const highRiskIntermediaries = intermediaries.filter(i => 
      i.riskLevel === RiskLevel.HIGH || i.riskLevel === RiskLevel.CRITICAL
    );
    riskScore += highRiskIntermediaries.length * 20;
    
    if (riskScore >= 80) return RiskLevel.CRITICAL;
    if (riskScore >= 60) return RiskLevel.HIGH;
    if (riskScore >= 40) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private analyzeTransactionPatterns(transactions: any[]): any {
    // Analyze transaction patterns for purpose inference
    const amounts = transactions.map(tx => tx.amount);
    const frequencies = this.calculateTransactionFrequencies(transactions);
    
    return {
      hasInvestmentCharacteristics: this.hasInvestmentCharacteristics(amounts, frequencies),
      hasSpeculationCharacteristics: this.hasSpeculationCharacteristics(amounts, frequencies),
      hasArbitrageCharacteristics: this.hasArbitrageCharacteristics(amounts, frequencies),
      hasTaxEvasionCharacteristics: this.hasTaxEvasionCharacteristics(amounts, frequencies),
      hasMoneyLaunderingCharacteristics: this.hasMoneyLaunderingCharacteristics(amounts, frequencies)
    };
  }

  private calculateTransactionFrequencies(transactions: any[]): number[] {
    // Calculate transaction frequencies
    const frequencies = [];
    
    for (let i = 1; i < transactions.length; i++) {
      const interval = transactions[i].timestamp - transactions[i-1].timestamp;
      frequencies.push(interval);
    }
    
    return frequencies;
  }

  private hasInvestmentCharacteristics(amounts: number[], frequencies: number[]): boolean {
    // Check for investment characteristics
    return amounts.some(amount => amount > 50000) && frequencies.some(freq => freq > 7 * 24 * 60 * 60 * 1000); // Large amounts, long intervals
  }

  private hasSpeculationCharacteristics(amounts: number[], frequencies: number[]): boolean {
    // Check for speculation characteristics
    return amounts.some(amount => amount > 10000 && amount < 100000) && 
           frequencies.some(freq => freq < 24 * 60 * 60 * 1000); // Medium amounts, daily frequency
  }

  private hasArbitrageCharacteristics(amounts: number[], frequencies: number[]): boolean {
    // Check for arbitrage characteristics
    return amounts.some(amount => amount > 1000) && 
           frequencies.some(freq => freq < 60 * 60 * 1000); // Small amounts, hourly frequency
  }

  private hasTaxEvasionCharacteristics(amounts: number[], frequencies: number[]): boolean {
    // Check for tax evasion characteristics
    return amounts.some(amount => amount < 10000 && amount > 9000) && 
           frequencies.some(freq => freq > 0); // Amounts just below thresholds
  }

  private hasMoneyLaunderingCharacteristics(amounts: number[], frequencies: number[]): boolean {
    // Check for money laundering characteristics
    return amounts.some(amount => amount > 50000) && 
           frequencies.some(freq => freq < 30 * 60 * 1000); // Large amounts, frequent transactions
  }

  private calculateRegulatoryDifference(reg1: JurisdictionProfile, reg2: JurisdictionProfile): any {
    // Calculate regulatory difference between two jurisdictions
    let differenceScore = 0;
    
    // Compare KYC requirements
    if (reg1.financialRegulations.kycRequirements.identityVerification !== 
        reg2.financialRegulations.kycRequirements.identityVerification) {
      differenceScore += 20;
    }
    
    // Compare AML thresholds
    if (reg1.financialRegulations.amlThresholds.reportingThreshold !== 
        reg2.financialRegulations.amlThresholds.reportingThreshold) {
      differenceScore += 25;
    }
    
    return {
      riskScore: differenceScore,
      hasSignificantDifferences: differenceScore > 30
    };
  }

  private async analyzeTreatyBenefits(flow: CrossBorderFlow): Promise<any> {
    // Analyze treaty benefits for a flow
    const sourceJur = this.jurisdictionDatabase.get(flow.sourceJurisdiction);
    const targetJur = this.jurisdictionDatabase.get(flow.targetJurisdiction);
    
    // Check for tax treaties
    const hasTaxTreaty = this.checkTaxTreaty(sourceJur, targetJur);
    
    // Check for trade agreements
    const hasTradeAgreement = this.checkTradeAgreement(sourceJur, targetJur);
    
    const estimatedBenefit = (hasTaxTreaty ? 1000 : 0) + (hasTradeAgreement ? 500 : 0);
    
    return {
      hasExploitableBenefits: estimatedBenefit > 0,
      estimatedBenefit,
      exploitedTreaties: [
        ...(hasTaxTreaty ? ['tax_treaty'] : []),
        ...(hasTradeAgreement ? ['trade_agreement'] : [])
      ]
    };
  }

  private checkTaxTreaty(jur1: JurisdictionProfile, jur2: JurisdictionProfile): boolean {
    // Simplified tax treaty check
    const treatyPairs = [
      ['US', 'UK'], ['US', 'CA'], ['DE', 'FR'], ['JP', 'SG']
    ];
    
    const pair1 = [jur1.isoCode, jur2.isoCode].sort();
    const pair2 = [jur2.isoCode, jur1.isoCode].sort();
    
    return treatyPairs.some(pair => 
      pair[0] === pair1[0] && pair[1] === pair1[1]
    );
  }

  private checkTradeAgreement(jur1: JurisdictionProfile, jur2: JurisdictionProfile): boolean {
    // Simplified trade agreement check
    const tradeAgreements = [
      ['US', 'MX'], ['EU', 'UK'], ['CN', 'JP'], ['KR', 'US']
    ];
    
    const pair1 = [jur1.isoCode, jur2.isoCode].sort();
    const pair2 = [jur2.isoCode, jur1.isoCode].sort();
    
    return tradeAgreements.some(pair => 
      pair[0] === pair1[0] && pair[1] === pair1[1]
    );
  }

  private async identifyRegulatoryArbitragePatterns(flows: CrossBorderFlow[]): Promise<any[]> {
    // Identify regulatory arbitrage patterns
    const patterns = [];
    
    // Look for flows that exploit regulatory differences
    for (const flow of flows) {
      const sourceJur = this.jurisdictionDatabase.get(flow.sourceJurisdiction);
      const targetJur = this.jurisdictionDatabase.get(flow.targetJurisdiction);
      
      if (sourceJur && targetJur) {
        const regDiff = this.calculateRegulatoryDifference(sourceJur, targetJur);
        
        if (regDiff.hasSignificantDifferences) {
          patterns.push({
            flows: [flow],
            jurisdictions: [flow.sourceJurisdiction, flow.targetJurisdiction],
            regulatoryDifferences: regDiff,
            estimatedProfit: regDiff.riskScore * 50,
            confidence: 0.8
          });
        }
      }
    }
    
    return patterns;
  }

  private async identifyTaxArbitrageOpportunities(flows: CrossBorderFlow[]): Promise<any[]> {
    // Identify tax arbitrage opportunities
    const opportunities = [];
    
    // Look for flows that exploit tax differences
    for (const flow of flows) {
      const sourceJur = this.jurisdictionDatabase.get(flow.sourceJurisdiction);
      const targetJur = this.jurisdictionDatabase.get(flow.targetJurisdiction);
      
      if (sourceJur && targetJur && sourceJur.taxJurisdiction && targetJur.taxJurisdiction) {
        const taxDiff = this.calculateTaxDifference(sourceJur, targetJur);
        
        if (taxDiff.hasSignificantDifference) {
          opportunities.push({
            flows: [flow],
            jurisdictions: [flow.sourceJurisdiction, flow.targetJurisdiction],
            taxDifferences: taxDiff,
            taxBenefit: taxDiff.estimatedBenefit,
            confidence: 0.7
          });
        }
      }
    }
    
    return opportunities;
  }

  private calculateTaxDifference(jur1: JurisdictionProfile, jur2: JurisdictionProfile): any {
    // Calculate tax difference between jurisdictions
    // Simplified implementation
    const taxRates = {
      'US': 0.21,
      'UK': 0.19,
      'DE': 0.15,
      'FR': 0.16,
      'JP': 0.23,
      'SG': 0.17
    };
    
    const tax1 = taxRates[jur1.isoCode] || 0.20;
    const tax2 = taxRates[jur2.isoCode] || 0.20;
    const difference = Math.abs(tax1 - tax2);
    
    return {
      hasSignificantDifference: difference > 0.02, // 2% difference
      estimatedBenefit: difference * 10000, // Simplified calculation
      tax1,
      tax2
    };
  }

  private async analyzeFlowRoute(flow: CrossBorderFlow): Promise<any> {
    // Analyze the flow route
    return {
      routeComplexity: flow.route.path.length,
      highRiskIntermediaries: flow.intermediaries.filter(i => 
        i.riskLevel === RiskLevel.HIGH || i.riskLevel === RiskLevel.CRITICAL
      ).length,
      privacyToolsUsed: this.detectPrivacyToolsInRoute(flow.route),
      unusualPatterns: this.detectUnusualRoutePatterns(flow.route)
    };
  }

  private async analyzeFlowTiming(flow: CrossBorderFlow): Promise<any> {
    // Analyze the flow timing
    return {
      duration: flow.timing.duration,
      frequency: flow.timing.frequency,
      regularity: flow.timing.regularity,
      unusualPatterns: flow.timing.unusualPatterns,
      coordinationIndicators: this.detectCoordinationIndicators(flow.timing)
    };
  }

  private async analyzeFlowPurpose(flow: CrossBorderFlow): Promise<any> {
    // Analyze the flow purpose
    return {
      primaryPurpose: flow.purpose,
      riskLevel: this.getPurposeRiskLevel(flow.purpose),
      complianceIssues: this.checkPurposeCompliance(flow.purpose),
      indicators: this.getPurposeIndicators(flow.purpose, flow.transactions)
    };
  }

  private async analyzeFlowIntermediaries(flow: CrossBorderFlow): Promise<any> {
    // Analyze the flow intermediaries
    return {
      totalIntermediaries: flow.intermediaries.length,
      highRiskCount: flow.intermediaries.filter(i => 
        i.riskLevel === RiskLevel.HIGH || i.riskLevel === RiskLevel.CRITICAL
      ).length,
      suspiciousCount: flow.intermediaries.filter(i => i.suspicious).length,
      types: flow.intermediaries.map(i => i.type),
      jurisdictions: flow.intermediaries.map(i => i.jurisdiction)
    };
  }

  private async analyzeFlowRisk(flow: CrossBorderFlow): Promise<any> {
    // Analyze the flow risk
    return {
      riskScore: flow.riskScore,
      riskFactors: this.identifyRiskFactors(flow),
      mitigationRecommendations: this.generateMitigationRecommendations(flow)
    };
  }

  private detectPrivacyToolsInRoute(route: FlowRoute): boolean {
    // Detect privacy tools in route
    return route.methods.some(method => 
      method.toLowerCase().includes('privacy') ||
      method.toLowerCase().includes('mixer') ||
      method.toLowerCase().includes('tumbler')
    );
  }

  private detectUnusualRoutePatterns(route: FlowRoute): any[] {
    // Detect unusual route patterns
    const patterns = [];
    
    if (route.path.length > 5) {
      patterns.push({
        type: 'complex_route',
        description: 'Unusually complex route',
        severity: RiskLevel.MEDIUM
      });
    }
    
    return patterns;
  }

  private detectCoordinationIndicators(timing: FlowTiming): any[] {
    // Detect coordination indicators in timing
    const indicators = [];
    
    if (timing.regularity === 'regular' && timing.frequency > 1) {
      indicators.push({
        type: 'coordinated_timing',
        description: 'Regular high-frequency timing',
        severity: RiskLevel.MEDIUM
      });
    }
    
    return indicators;
  }

  private getPurposeRiskLevel(purpose: FlowPurpose): RiskLevel {
    // Get risk level for purpose
    const riskLevels = {
      [FlowPurpose.PERSONAL_USE]: RiskLevel.LOW,
      [FlowPurpose.BUSINESS_TRANSACTION]: RiskLevel.LOW,
      [FlowPurpose.INVESTMENT]: RiskLevel.MEDIUM,
      [FlowPurpose.SPECULATION]: RiskLevel.MEDIUM,
      [FlowPurpose.ARBITRAGE]: RiskLevel.HIGH,
      [FlowPurpose.TAX_EVASION]: RiskLevel.HIGH,
      [FlowPurpose.MONEY_LAUNDERING]: RiskLevel.CRITICAL,
      [FlowPurpose.REGULATORY_ARBITRAGE]: RiskLevel.HIGH
    };
    
    return riskLevels[purpose] || RiskLevel.MEDIUM;
  }

  private checkPurposeCompliance(purpose: FlowPurpose): string[] {
    // Check purpose compliance
    const issues = [];
    
    if (purpose === FlowPurpose.TAX_EVASION) {
      issues.push('Potential tax evasion');
    }
    
    if (purpose === FlowPurpose.MONEY_LAUNDERING) {
      issues.push('Potential money laundering');
    }
    
    return issues;
  }

  private getPurposeIndicators(purpose: FlowPurpose, transactions: any[]): string[] {
    // Get indicators for purpose
    const indicators = [];
    
    if (purpose === FlowPurpose.ARBITRAGE) {
      indicators.push('Quick round-trip transactions');
    }
    
    if (purpose === FlowPurpose.STRUCTURING) {
      indicators.push('Amounts just below thresholds');
    }
    
    return indicators;
  }

  private identifyRiskFactors(flow: CrossBorderFlow): string[] {
    // Identify risk factors
    const factors = [];
    
    if (flow.riskScore > 70) {
      factors.push('High overall risk score');
    }
    
    if (flow.suspiciousIndicators.length > 0) {
      factors.push('Suspicious indicators present');
    }
    
    return factors;
  }

  private generateMitigationRecommendations(flow: CrossBorderFlow): string[] {
    // Generate mitigation recommendations
    const recommendations = [];
    
    if (flow.riskScore > 80) {
      recommendations.push('Enhanced monitoring required');
    }
    
    if (flow.suspiciousIndicators.some(si => si.type === SuspiciousIndicatorType.ROUND_TRIPPING)) {
      recommendations.push('Investigate round-tripping pattern');
    }
    
    return recommendations;
  }
}
