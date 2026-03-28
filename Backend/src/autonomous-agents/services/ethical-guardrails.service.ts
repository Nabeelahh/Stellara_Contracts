import { Injectable, Logger } from '@nestjs/common';
import { 
  EthicalConstraint,
  EthicalType,
  Agent,
  AgentState,
  MarketConditions,
  NegotiationTerms,
  DecisionRationale,
  EthicalConsideration
} from '../interfaces/agent.interface';

@Injectable()
export class EthicalGuardrailsService {
  private readonly logger = new Logger(EthicalGuardrailsService.name);
  private ethicalRules = new Map<EthicalType, EthicalRule>();

  constructor() {
    this.initializeEthicalRules();
  }

  private initializeEthicalRules(): void {
    // Fairness rules
    this.ethicalRules.set(EthicalType.FAIRNESS, {
      name: 'Fairness',
      description: 'Ensure all actions are fair to all market participants',
      validator: this.validateFairness.bind(this),
      enforcer: this.enforceFairness.bind(this),
      severity: 'high',
      enabled: true
    });

    // Market manipulation rules
    this.ethicalRules.set(EthicalType.MARKET_MANIPULATION, {
      name: 'Market Manipulation Prevention',
      description: 'Prevent actions that manipulate market prices',
      validator: this.validateMarketManipulation.bind(this),
      enforcer: this.enforceMarketManipulation.bind(this),
      severity: 'critical',
      enabled: true
    });

    // Conflict of interest rules
    this.ethicalRules.set(EthicalType.CONFLICT_OF_INTEREST, {
      name: 'Conflict of Interest Prevention',
      description: 'Prevent actions with conflicts of interest',
      validator: this.validateConflictOfInterest.bind(this),
      enforcer: this.enforceConflictOfInterest.bind(this),
      severity: 'high',
      enabled: true
    });

    // Social welfare rules
    this.ethicalRules.set(EthicalType.SOCIAL_WELFARE, {
      name: 'Social Welfare Protection',
      description: 'Ensure actions contribute positively to social welfare',
      validator: this.validateSocialWelfare.bind(this),
      enforcer: this.enforceSocialWelfare.bind(this),
      severity: 'medium',
      enabled: true
    });

    // Transparency rules
    this.ethicalRules.set(EthicalType.TRANSPARENCY, {
      name: 'Transparency Requirement',
      description: 'Ensure all actions are transparent and explainable',
      validator: this.validateTransparency.bind(this),
      enforcer: this.enforceTransparency.bind(this),
      severity: 'medium',
      enabled: true
    });

    // Environmental impact rules
    this.ethicalRules.set(EthicalType.ENVIRONMENTAL_IMPACT, {
      name: 'Environmental Impact Assessment',
      description: 'Consider environmental impact of actions',
      validator: this.validateEnvironmentalImpact.bind(this),
      enforcer: this.enforceEnvironmentalImpact.bind(this),
      severity: 'low',
      enabled: true
    });
  }

  async validateAction(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<{
    valid: boolean;
    violations: EthicalViolation[];
    recommendations: string[];
  }> {
    const violations: EthicalViolation[] = [];
    const recommendations: string[] = [];

    this.logger.log(`Validating action ${proposedAction} for agent ${agent.id} against ethical constraints`);

    // Check all enabled ethical rules
    for (const [ethicalType, rule] of this.ethicalRules.entries()) {
      if (!rule.enabled) continue;

      try {
        const violation = await rule.validator(
          agent,
          proposedAction,
          terms,
          marketConditions,
          currentState
        );

        if (violation) {
          violations.push({
            type: ethicalType,
            severity: rule.severity,
            description: violation.description,
            impact: violation.impact,
            threshold: violation.threshold,
            actualValue: violation.actualValue,
            recommendation: violation.recommendation
          });

          recommendations.push(violation.recommendation);
        }
      } catch (error) {
        this.logger.error(`Error validating ethical rule ${ethicalType}:`, error);
      }
    }

    const valid = violations.length === 0;

    if (!valid) {
      this.logger.warn(`Ethical violations detected for agent ${agent.id}:`, violations);
    }

    return {
      valid,
      violations,
      recommendations
    };
  }

  async enforceEthicalConstraints(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<{
    allowed: boolean;
    modifiedTerms?: NegotiationTerms;
    enforcementActions: EnforcementAction[];
  }> {
    const validation = await this.validateAction(
      agent,
      proposedAction,
      terms,
      marketConditions,
      currentState
    );

    if (validation.valid) {
      return {
        allowed: true,
        enforcementActions: []
      };
    }

    const enforcementActions: EnforcementAction[] = [];
    let modifiedTerms = { ...terms };

    // Apply enforcement for each violation
    for (const violation of validation.violations) {
      const rule = this.ethicalRules.get(violation.type);
      if (!rule) continue;

      try {
        const enforcement = await rule.enforcer(
          agent,
          proposedAction,
          modifiedTerms,
          violation,
          marketConditions
        );

        enforcementActions.push(enforcement);
        
        if (enforcement.modifiedTerms) {
          modifiedTerms = enforcement.modifiedTerms;
        }
      } catch (error) {
        this.logger.error(`Error enforcing ethical rule ${violation.type}:`, error);
      }
    }

    const allowed = enforcementActions.every(action => action.action !== 'block');

    return {
      allowed,
      modifiedTerms: modifiedTerms !== terms ? modifiedTerms : undefined,
      enforcementActions
    };
  }

  private async validateFairness(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check if action is fair to all participants
    const orderSize = terms.quantity * (terms.price || 0);
    const marketDepth = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);

    // Large orders relative to market depth may be unfair
    const marketImpactRatio = orderSize / marketDepth;
    
    if (marketImpactRatio > 0.1) { // More than 10% of market depth
      return {
        type: EthicalType.FAIRNESS,
        severity: 'high',
        description: 'Order size too large relative to market depth',
        impact: marketImpactRatio,
        threshold: 0.1,
        actualValue: marketImpactRatio,
        recommendation: 'Reduce order size to less than 10% of market depth'
      };
    }

    // Check price fairness
    if (terms.price) {
      const avgPrice = Object.values(marketConditions.price)
        .reduce((sum, price) => sum + price, 0) / Object.keys(marketConditions.price).length;
      const priceDeviation = Math.abs(terms.price - avgPrice) / avgPrice;

      if (priceDeviation > 0.05) { // More than 5% deviation from average
        return {
          type: EthicalType.FAIRNESS,
          severity: 'medium',
          description: 'Price deviates significantly from market average',
          impact: priceDeviation,
          threshold: 0.05,
          actualValue: priceDeviation,
          recommendation: 'Adjust price closer to market average'
        };
      }
    }

    return null;
  }

  private async validateMarketManipulation(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check for potential market manipulation patterns
    const manipulationScore = await this.calculateManipulationScore(
      proposedAction,
      terms,
      marketConditions,
      currentState
    );

    if (manipulationScore > 0.7) {
      return {
        type: EthicalType.MARKET_MANIPULATION,
        severity: 'critical',
        description: 'High probability of market manipulation',
        impact: manipulationScore,
        threshold: 0.7,
        actualValue: manipulationScore,
        recommendation: 'Modify action to reduce manipulation risk'
      };
    }

    return null;
  }

  private async validateConflictOfInterest(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check for conflicts of interest
    const conflictScore = await this.calculateConflictScore(
      agent,
      proposedAction,
      terms,
      currentState
    );

    if (conflictScore > 0.5) {
      return {
        type: EthicalType.CONFLICT_OF_INTEREST,
        severity: 'high',
        description: 'Potential conflict of interest detected',
        impact: conflictScore,
        threshold: 0.5,
        actualValue: conflictScore,
        recommendation: 'Review and mitigate conflicts of interest'
      };
    }

    return null;
  }

  private async validateSocialWelfare(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check impact on social welfare
    const welfareImpact = await this.calculateWelfareImpact(
      proposedAction,
      terms,
      marketConditions
    );

    if (welfareImpact < -0.3) { // Significant negative impact
      return {
        type: EthicalType.SOCIAL_WELFARE,
        severity: 'medium',
        description: 'Action has negative impact on social welfare',
        impact: welfareImpact,
        threshold: -0.3,
        actualValue: welfareImpact,
        recommendation: 'Modify action to reduce negative welfare impact'
      };
    }

    return null;
  }

  private async validateTransparency(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check transparency of the action
    const transparencyScore = this.calculateTransparencyScore(proposedAction, terms);

    if (transparencyScore < 0.6) {
      return {
        type: EthicalType.TRANSPARENCY,
        severity: 'medium',
        description: 'Action lacks sufficient transparency',
        impact: 1 - transparencyScore,
        threshold: 0.6,
        actualValue: transparencyScore,
        recommendation: 'Increase transparency of action and decision process'
      };
    }

    return null;
  }

  private async validateEnvironmentalImpact(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<EthicalViolation | null> {
    // Check environmental impact (simplified for DeFi)
    const environmentalScore = await this.calculateEnvironmentalImpact(
      proposedAction,
      terms
    );

    if (environmentalScore < 0.4) {
      return {
        type: EthicalType.ENVIRONMENTAL_IMPACT,
        severity: 'low',
        description: 'Action has negative environmental impact',
        impact: environmentalScore,
        threshold: 0.4,
        actualValue: environmentalScore,
        recommendation: 'Consider more environmentally friendly alternatives'
      };
    }

    return null;
  }

  private async enforceFairness(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    const modifiedTerms = { ...terms };

    if (violation.description.includes('Order size too large')) {
      const marketDepth = Object.values(marketConditions.liquidity)
        .reduce((sum, liq) => sum + liq, 0);
      const maxAllowedSize = marketDepth * 0.05; // 5% of market depth
      
      if (terms.quantity * (terms.price || 0) > maxAllowedSize) {
        modifiedTerms.quantity = maxAllowedSize / (terms.price || 1);
      }
    }

    if (violation.description.includes('Price deviates significantly')) {
      const avgPrice = Object.values(marketConditions.price)
        .reduce((sum, price) => sum + price, 0) / Object.keys(marketConditions.price).length;
      
      if (terms.price) {
        const maxDeviation = avgPrice * 0.02; // 2% deviation allowed
        modifiedTerms.price = Math.max(avgPrice - maxDeviation, Math.min(avgPrice + maxDeviation, terms.price));
      }
    }

    return {
      type: 'modify',
      description: 'Modified terms to ensure fairness',
      modifiedTerms,
      severity: violation.severity
    };
  }

  private async enforceMarketManipulation(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    // Block actions with high manipulation risk
    if (violation.impact > 0.8) {
      return {
        type: 'block',
        description: 'Action blocked due to high market manipulation risk',
        severity: 'critical'
      };
    }

    // For medium risk, add delay and monitoring
    return {
      type: 'monitor',
      description: 'Action flagged for monitoring due to manipulation concerns',
      severity: 'high',
      monitoringLevel: 'high',
      additionalChecks: ['price_impact_analysis', 'volume_pattern_analysis']
    };
  }

  private async enforceConflictOfInterest(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    // Require additional approval for conflicts of interest
    return {
      type: 'require_approval',
      description: 'Additional approval required due to conflict of interest',
      severity: 'high',
      requiredApprovals: ['compliance_officer', 'ethics_committee'],
      approvalDeadline: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    };
  }

  private async enforceSocialWelfare(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    const modifiedTerms = { ...terms };

    // Add welfare contribution requirement
    if (!modifiedTerms.conditions) {
      modifiedTerms.conditions = [];
    }
    
    modifiedTerms.conditions.push(
      'Include 0.1% fee for social welfare fund'
    );

    return {
      type: 'modify',
      description: 'Modified terms to include social welfare contribution',
      modifiedTerms,
      severity: violation.severity
    };
  }

  private async enforceTransparency(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    return {
      type: 'require_documentation',
      description: 'Additional documentation required for transparency',
      severity: 'medium',
      requiredDocumentation: [
        'detailed_decision_rationale',
        'market_analysis_report',
        'risk_assessment_document'
      ],
      documentationDeadline: new Date(Date.now() + 2 * 60 * 60 * 1000) // 2 hours
    };
  }

  private async enforceEnvironmentalImpact(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ): Promise<EnforcementAction> {
    const modifiedTerms = { ...terms };

    // Add carbon offset requirement
    if (!modifiedTerms.conditions) {
      modifiedTerms.conditions = [];
    }
    
    modifiedTerms.conditions.push(
      'Include carbon offset for environmental impact'
    );

    return {
      type: 'modify',
      description: 'Modified terms to include environmental mitigation',
      modifiedTerms,
      severity: violation.severity
    };
  }

  private async calculateManipulationScore(
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ): Promise<number> {
    let score = 0;

    // Check for wash trading patterns
    const washTradingRisk = this.checkWashTradingRisk(terms, currentState);
    score += washTradingRisk * 0.3;

    // Check for spoofing patterns
    const spoofingRisk = this.checkSpoofingRisk(terms, marketConditions);
    score += spoofingRisk * 0.3;

    // Check for pump and dump patterns
    const pumpDumpRisk = this.checkPumpDumpRisk(terms, marketConditions);
    score += pumpDumpRisk * 0.4;

    return Math.min(score, 1);
  }

  private async calculateConflictScore(
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    currentState: AgentState
  ): Promise<number> {
    let score = 0;

    // Check self-dealing
    const selfDealingRisk = this.checkSelfDealingRisk(terms, agent);
    score += selfDealingRisk * 0.4;

    // Check front-running
    const frontRunningRisk = this.checkFrontRunningRisk(proposedAction, currentState);
    score += frontRunningRisk * 0.3;

    // Check information asymmetry
    const infoAsymmetryRisk = this.checkInformationAsymmetryRisk(agent, proposedAction);
    score += infoAsymmetryRisk * 0.3;

    return Math.min(score, 1);
  }

  private async calculateWelfareImpact(
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Simplified welfare impact calculation
    const marketEfficiency = this.calculateMarketEfficiencyImpact(terms, marketConditions);
    const accessibilityImpact = this.calculateAccessibilityImpact(terms);
    const stabilityImpact = this.calculateStabilityImpact(proposedAction, marketConditions);

    return (marketEfficiency + accessibilityImpact + stabilityImpact) / 3;
  }

  private calculateTransparencyScore(proposedAction: string, terms: NegotiationTerms): number {
    let score = 0.5; // Base score

    // Higher score for clear terms
    if (terms.price && terms.quantity && terms.currency) {
      score += 0.2;
    }

    // Higher score for documented conditions
    if (terms.conditions && terms.conditions.length > 0) {
      score += 0.2;
    }

    // Lower score for complex or obscure actions
    const complexity = this.getActionComplexity(proposedAction);
    score -= complexity * 0.05;

    return Math.min(Math.max(score, 0), 1);
  }

  private async calculateEnvironmentalImpact(
    proposedAction: string,
    terms: NegotiationTerms
  ): Promise<number> {
    // Simplified environmental impact for DeFi
    let impact = 0.8; // Base impact (neutral)

    // Energy consumption consideration
    const energyImpact = this.calculateEnergyImpact(proposedAction);
    impact -= energyImpact * 0.2;

    // Blockchain efficiency
    const blockchainEfficiency = this.calculateBlockchainEfficiency(terms);
    impact += blockchainEfficiency * 0.2;

    return Math.min(Math.max(impact, 0), 1);
  }

  private checkWashTradingRisk(terms: NegotiationTerms, currentState: AgentState): number {
    // Check for patterns indicative of wash trading
    const recentPositions = currentState.positions.slice(-5);
    let risk = 0;

    for (const position of recentPositions) {
      const timeDiff = Date.now() - position.timestamp.getTime();
      if (timeDiff < 60000 && position.amount > 0) { // Within 1 minute
        risk += 0.2;
      }
    }

    return Math.min(risk, 1);
  }

  private checkSpoofingRisk(terms: NegotiationTerms, marketConditions: MarketConditions): number {
    // Check for large orders that are quickly cancelled
    const orderSize = terms.quantity * (terms.price || 0);
    const marketVolume = Object.values(marketConditions.volume)
      .reduce((sum, vol) => sum + vol, 0);

    return Math.min(orderSize / marketVolume, 1);
  }

  private checkPumpDumpRisk(terms: NegotiationTerms, marketConditions: MarketConditions): number {
    // Check for patterns indicative of pump and dump
    const priceVolatility = this.calculateAverageVolatility(marketConditions);
    const orderSize = terms.quantity * (terms.price || 0);

    return Math.min((priceVolatility * orderSize) / 1000000, 1);
  }

  private checkSelfDealingRisk(terms: NegotiationTerms, agent: Agent): number {
    // Check if agent is trading with itself or related entities
    // Simplified check
    return 0.1; // Low risk for most cases
  }

  private checkFrontRunningRisk(proposedAction: string, currentState: AgentState): number {
    // Check if agent might be front-running other transactions
    const actionSpeed = this.getActionSpeed(proposedAction);
    return actionSpeed > 0.8 ? 0.3 : 0.1;
  }

  private checkInformationAsymmetryRisk(agent: Agent, proposedAction: string): number {
    // Check for potential information asymmetry
    return 0.1; // Low risk for most cases
  }

  private calculateMarketEfficiencyImpact(terms: NegotiationTerms, marketConditions: MarketConditions): number {
    // Calculate impact on market efficiency
    const liquidityContribution = this.estimateLiquidityContribution(terms);
    const priceDiscoveryContribution = this.estimatePriceDiscoveryContribution(terms, marketConditions);

    return (liquidityContribution + priceDiscoveryContribution) / 2;
  }

  private calculateAccessibilityImpact(terms: NegotiationTerms): number {
    // Calculate impact on market accessibility
    const minOrderSize = terms.quantity * (terms.price || 0);
    return minOrderSize < 100 ? 0.2 : minOrderSize < 1000 ? 0.1 : 0;
  }

  private calculateStabilityImpact(proposedAction: string, marketConditions: MarketConditions): number {
    // Calculate impact on market stability
    const volatility = this.calculateAverageVolatility(marketConditions);
    return volatility < 0.1 ? 0.2 : volatility < 0.2 ? 0.1 : -0.1;
  }

  private calculateEnergyImpact(proposedAction: string): number {
    // Calculate energy consumption impact
    const complexity = this.getActionComplexity(proposedAction);
    return Math.max(0, 1 - complexity / 10);
  }

  private calculateBlockchainEfficiency(terms: NegotiationTerms): number {
    // Calculate blockchain efficiency impact
    return 0.1; // Placeholder
  }

  private estimateLiquidityContribution(terms: NegotiationTerms): number {
    // Estimate contribution to market liquidity
    return proposedAction.toLowerCase().includes('liquidity') ? 0.3 : 0.1;
  }

  private estimatePriceDiscoveryContribution(terms: NegotiationTerms, marketConditions: MarketConditions): number {
    // Estimate contribution to price discovery
    return 0.1; // Placeholder
  }

  private getActionComplexity(action: string): number {
    const complexities: { [key: string]: number } = {
      'buy': 2,
      'sell': 2,
      'hold': 1,
      'provide_liquidity': 5,
      'borrow': 4,
      'lend': 4,
      'arbitrage': 8
    };
    
    return complexities[action.toLowerCase()] || 5;
  }

  private getActionSpeed(action: string): number {
    // Estimate execution speed of action
    const speeds: { [key: string]: number } = {
      'buy': 0.7,
      'sell': 0.8,
      'hold': 0.2,
      'provide_liquidity': 0.5,
      'borrow': 0.6,
      'lend': 0.6,
      'arbitrage': 0.9
    };
    
    return speeds[action.toLowerCase()] || 0.5;
  }

  private calculateAverageVolatility(marketConditions: MarketConditions): number {
    const volatilities = Object.values(marketConditions.volatility);
    return volatilities.reduce((sum, vol) => sum + vol, 0) / volatilities.length;
  }

  async getEthicalReport(
    agentId: string,
    timeRange: { start: Date; end: Date }
  ): Promise<EthicalReport> {
    // Generate ethical compliance report for time range
    this.logger.log(`Generating ethical report for agent ${agentId}`);

    return {
      agentId,
      timeRange,
      totalActions: 0,
      violations: [],
      complianceScore: 0,
      recommendations: [],
      generatedAt: new Date()
    };
  }

  updateEthicalConstraints(constraints: EthicalConstraint[]): void {
    // Update ethical constraints configuration
    this.logger.log('Updating ethical constraints configuration');
    
    for (const constraint of constraints) {
      const rule = this.ethicalRules.get(constraint.type);
      if (rule) {
        rule.enabled = constraint.action !== 'disable';
        this.logger.log(`Updated ${constraint.type} constraint: ${constraint.action}`);
      }
    }
  }

  getEthicalRules(): Map<EthicalType, EthicalRule> {
    return new Map(this.ethicalRules);
  }
}

interface EthicalRule {
  name: string;
  description: string;
  validator: (
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    marketConditions: MarketConditions,
    currentState: AgentState
  ) => Promise<EthicalViolation | null>;
  enforcer: (
    agent: Agent,
    proposedAction: string,
    terms: NegotiationTerms,
    violation: EthicalViolation,
    marketConditions: MarketConditions
  ) => Promise<EnforcementAction>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
}

interface EthicalViolation {
  type: EthicalType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  impact: number;
  threshold: number;
  actualValue: number;
  recommendation: string;
}

interface EnforcementAction {
  type: 'block' | 'modify' | 'require_approval' | 'monitor' | 'require_documentation';
  description: string;
  modifiedTerms?: NegotiationTerms;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  monitoringLevel?: 'low' | 'medium' | 'high';
  additionalChecks?: string[];
  requiredApprovals?: string[];
  approvalDeadline?: Date;
  requiredDocumentation?: string[];
  documentationDeadline?: Date;
}

interface EthicalReport {
  agentId: string;
  timeRange: { start: Date; end: Date };
  totalActions: number;
  violations: EthicalViolation[];
  complianceScore: number;
  recommendations: string[];
  generatedAt: Date;
}
