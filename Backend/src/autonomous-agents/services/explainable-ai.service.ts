import { Injectable, Logger } from '@nestjs/common';
import { 
  DecisionRationale,
  RationaleFactor,
  EthicalConsideration,
  Alternative,
  Agent,
  AgentState,
  MarketConditions,
  NegotiationTerms,
  EthicalType
} from '../interfaces/agent.interface';

@Injectable()
export class ExplainableAIService {
  private readonly logger = new Logger(ExplainableAIService.name);

  async generateDecisionRationale(
    agent: Agent,
    currentState: AgentState,
    proposedAction: string,
    marketConditions: MarketConditions,
    alternatives?: Alternative[]
  ): Promise<DecisionRationale> {
    try {
      // Analyze factors influencing the decision
      const factors = await this.analyzeDecisionFactors(
        agent,
        currentState,
        proposedAction,
        marketConditions
      );

      // Evaluate ethical considerations
      const ethicalConsiderations = await this.evaluateEthicalConstraints(
        proposedAction,
        agent,
        marketConditions
      );

      // Calculate confidence based on data quality and model certainty
      const confidence = this.calculateDecisionConfidence(
        factors,
        ethicalConsiderations,
        currentState
      );

      // Generate or validate alternatives
      const validatedAlternatives = alternatives ? 
        await this.validateAlternatives(alternatives, agent, currentState) :
        await this.generateAlternatives(currentState, agent, proposedAction);

      // Create reasoning narrative
      const reasoning = await this.generateReasoningNarrative(
        factors,
        ethicalConsiderations,
        proposedAction,
        agent
      );

      // Determine primary factor
      const primaryFactor = this.identifyPrimaryFactor(factors);

      return {
        primaryFactor,
        factors,
        confidence,
        ethicalConsiderations,
        alternatives: validatedAlternatives,
        reasoning
      };
    } catch (error) {
      this.logger.error('Failed to generate decision rationale:', error);
      
      return {
        primaryFactor: 'Error in decision process',
        factors: [],
        confidence: 0,
        ethicalConsiderations: [],
        alternatives: [],
        reasoning: `Error occurred while generating rationale: ${error.message}`
      };
    }
  }

  private async analyzeDecisionFactors(
    agent: Agent,
    currentState: AgentState,
    proposedAction: string,
    marketConditions: MarketConditions
  ): Promise<RationaleFactor[]> {
    const factors: RationaleFactor[] = [];

    // Market conditions factor
    const marketVolatility = this.calculateAverageVolatility(marketConditions);
    factors.push({
      name: 'Market Volatility',
      weight: 0.2,
      value: marketVolatility,
      impact: marketVolatility > 0.3 ? 'negative' : marketVolatility > 0.15 ? 'neutral' : 'positive'
    });

    // Liquidity factor
    const totalLiquidity = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);
    factors.push({
      name: 'Market Liquidity',
      weight: 0.15,
      value: totalLiquidity,
      impact: totalLiquidity > 1000000 ? 'positive' : totalLiquidity > 500000 ? 'neutral' : 'negative'
    });

    // Agent's current position factor
    const positionValue = this.calculateTotalPositionValue(currentState.positions);
    factors.push({
      name: 'Current Position Value',
      weight: 0.25,
      value: positionValue,
      impact: positionValue > 10000 ? 'positive' : positionValue > 5000 ? 'neutral' : 'negative'
    });

    // Risk exposure factor
    const riskExposure = this.calculateRiskExposure(currentState, marketConditions);
    factors.push({
      name: 'Risk Exposure',
      weight: 0.2,
      value: riskExposure,
      impact: riskExposure < 0.1 ? 'positive' : riskExposure < 0.2 ? 'neutral' : 'negative'
    });

    // Historical performance factor
    const historicalPerformance = await this.getHistoricalPerformance(agent.id);
    factors.push({
      name: 'Historical Performance',
      weight: 0.1,
      value: historicalPerformance,
      impact: historicalPerformance > 0.05 ? 'positive' : historicalPerformance > 0 ? 'neutral' : 'negative'
    });

    // Action-specific factors
    const actionFactors = await this.analyzeActionSpecificFactors(
      proposedAction,
      currentState,
      marketConditions
    );
    factors.push(...actionFactors);

    return factors;
  }

  private async evaluateEthicalConstraints(
    proposedAction: string,
    agent: Agent,
    marketConditions: MarketConditions
  ): Promise<EthicalConsideration[]> {
    const considerations: EthicalConsideration[] = [];

    // Fairness consideration
    const fairnessScore = await this.evaluateFairness(proposedAction, marketConditions);
    considerations.push({
      type: EthicalType.FAIRNESS,
      constraint: 'Action must not exploit market inefficiencies',
      satisfied: fairnessScore > 0.7,
      impact: fairnessScore
    });

    // Market manipulation check
    const manipulationRisk = await this.evaluateMarketManipulationRisk(proposedAction, marketConditions);
    considerations.push({
      type: EthicalType.MARKET_MANIPULATION,
      constraint: 'No market manipulation or price manipulation',
      satisfied: manipulationRisk < 0.3,
      impact: 1 - manipulationRisk
    });

    // Conflict of interest check
    const conflictRisk = await this.evaluateConflictOfInterest(proposedAction, agent);
    considerations.push({
      type: EthicalType.CONFLICT_OF_INTEREST,
      constraint: 'No conflicts of interest in decision making',
      satisfied: conflictRisk < 0.2,
      impact: 1 - conflictRisk
    });

    // Social welfare impact
    const welfareImpact = await this.evaluateSocialWelfareImpact(proposedAction, marketConditions);
    considerations.push({
      type: EthicalType.SOCIAL_WELFARE,
      constraint: 'Action should contribute positively to market efficiency',
      satisfied: welfareImpact > 0,
      impact: welfareImpact
    });

    // Transparency consideration
    const transparencyScore = await this.evaluateTransparency(proposedAction);
    considerations.push({
      type: EthicalType.TRANSPARENCY,
      constraint: 'Decision process must be transparent and explainable',
      satisfied: transparencyScore > 0.8,
      impact: transparencyScore
    });

    return considerations;
  }

  private calculateDecisionConfidence(
    factors: RationaleFactor[],
    ethicalConsiderations: EthicalConsideration[],
    currentState: AgentState
  ): number {
    // Base confidence from factor analysis
    const factorConfidence = this.calculateFactorConfidence(factors);
    
    // Ethical confidence
    const ethicalConfidence = this.calculateEthicalConfidence(ethicalConsiderations);
    
    // Data quality confidence
    const dataQualityConfidence = this.calculateDataQualityConfidence(currentState);
    
    // Model confidence (would come from ML model)
    const modelConfidence = 0.85; // Placeholder

    // Weighted combination
    const weights = {
      factors: 0.4,
      ethical: 0.3,
      data: 0.2,
      model: 0.1
    };

    const overallConfidence = 
      factorConfidence * weights.factors +
      ethicalConfidence * weights.ethical +
      dataQualityConfidence * weights.data +
      modelConfidence * weights.model;

    return Math.min(Math.max(overallConfidence, 0), 1);
  }

  private async validateAlternatives(
    alternatives: Alternative[],
    agent: Agent,
    currentState: AgentState
  ): Promise<Alternative[]> {
    const validatedAlternatives: Alternative[] = [];

    for (const alternative of alternatives) {
      const validation = await this.validateAlternative(alternative, agent, currentState);
      
      validatedAlternatives.push({
        ...alternative,
        rejected: !validation.valid,
        reason: validation.reason
      });
    }

    return validatedAlternatives;
  }

  private async generateAlternatives(
    currentState: AgentState,
    agent: Agent,
    proposedAction: string
  ): Promise<Alternative[]> {
    const alternatives: Alternative[] = [];

    // Generate alternative actions based on current state
    const possibleActions = await this.generatePossibleActions(currentState, agent);
    
    for (const action of possibleActions) {
      if (action !== proposedAction) {
        const expectedUtility = await this.estimateActionUtility(action, currentState, agent);
        const risk = await this.estimateActionRisk(action, currentState);
        
        alternatives.push({
          description: `Alternative: ${action}`,
          expectedUtility,
          risk,
          rejected: false,
          reason: 'Generated as alternative to proposed action'
        });
      }
    }

    // Sort by expected utility
    return alternatives.sort((a, b) => b.expectedUtility - a.expectedUtility).slice(0, 5);
  }

  private async generateReasoningNarrative(
    factors: RationaleFactor[],
    ethicalConsiderations: EthicalConsideration[],
    proposedAction: string,
    agent: Agent
  ): Promise<string> {
    const primaryFactors = factors
      .filter(f => f.impact === 'positive')
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3);

    const negativeFactors = factors
      .filter(f => f.impact === 'negative')
      .sort((a, b) => b.weight - a.weight);

    const ethicalIssues = ethicalConsiderations
      .filter(ec => !ec.satisfied)
      .map(ec => ec.type);

    let narrative = `Agent ${agent.name} decided to ${proposedAction} based on the following analysis:\n\n`;
    
    narrative += `**Primary Considerations:**\n`;
    for (const factor of primaryFactors) {
      narrative += `- ${factor.name}: ${factor.value.toFixed(3)} (Weight: ${factor.weight}, Impact: ${factor.impact})\n`;
    }

    if (negativeFactors.length > 0) {
      narrative += `\n**Risk Factors:**\n`;
      for (const factor of negativeFactors) {
        narrative += `- ${factor.name}: ${factor.value.toFixed(3)} (Weight: ${factor.weight}, Impact: ${factor.impact})\n`;
      }
    }

    if (ethicalIssues.length > 0) {
      narrative += `\n**Ethical Considerations:**\n`;
      narrative += `The following ethical constraints were identified: ${ethicalIssues.join(', ')}.\n`;
      
      for (const ec of ethicalConsiderations) {
        if (!ec.satisfied) {
          narrative += `- ${ec.constraint}: Not satisfied (Impact: ${ec.impact.toFixed(3)})\n`;
        }
      }
    } else {
      narrative += `\n**Ethical Considerations:**\n`;
      narrative += `All ethical constraints were satisfied.\n`;
    }

    narrative += `\n**Decision Logic:**\n`;
    narrative += `The action was selected after weighing ${factors.length} factors, `;
    narrative += `considering ${ethicalConsiderations.length} ethical constraints, `;
    narrative += `and evaluating ${await this.countAlternatives(proposedAction)} alternatives. `;
    narrative += `The decision prioritizes ${this.getDecisionPriorities(agent)} while maintaining ethical standards.\n`;

    return narrative;
  }

  private identifyPrimaryFactor(factors: RationaleFactor[]): string {
    // Find the factor with highest weighted impact
    let primaryFactor = factors[0]?.name || 'Unknown';
    let highestScore = -Infinity;

    for (const factor of factors) {
      const score = factor.weight * (factor.impact === 'positive' ? 1 : 
        factor.impact === 'negative' ? -1 : 0);
      
      if (score > highestScore) {
        highestScore = score;
        primaryFactor = factor.name;
      }
    }

    return primaryFactor;
  }

  private calculateAverageVolatility(marketConditions: MarketConditions): number {
    const volatilities = Object.values(marketConditions.volatility);
    return volatilities.reduce((sum, vol) => sum + vol, 0) / volatilities.length;
  }

  private calculateTotalPositionValue(positions: any[]): number {
    return positions.reduce((sum, pos) => sum + Math.abs(pos.amount * pos.currentPrice), 0);
  }

  private calculateRiskExposure(currentState: AgentState, marketConditions: MarketConditions): number {
    // Calculate portfolio risk based on position volatility and correlation
    let totalRisk = 0;
    
    for (const position of currentState.positions) {
      const assetVolatility = marketConditions.volatility[position.asset] || 0.2;
      const positionValue = Math.abs(position.amount * position.currentPrice);
      totalRisk += positionValue * assetVolatility;
    }
    
    const totalValue = this.calculateTotalPositionValue(currentState.positions);
    return totalValue > 0 ? totalRisk / totalValue : 0;
  }

  private async getHistoricalPerformance(agentId: string): Promise<number> {
    // This would fetch from database
    // For now, return a simulated performance metric
    return 0.03; // 3% average return
  }

  private async analyzeActionSpecificFactors(
    action: string,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<RationaleFactor[]> {
    const factors: RationaleFactor[] = [];

    switch (action.toLowerCase()) {
      case 'buy':
        factors.push({
          name: 'Buy Opportunity',
          weight: 0.1,
          value: this.evaluateBuyOpportunity(currentState, marketConditions),
          impact: 'positive'
        });
        break;

      case 'sell':
        factors.push({
          name: 'Sell Pressure',
          weight: 0.1,
          value: this.evaluateSellPressure(currentState, marketConditions),
          impact: 'neutral'
        });
        break;

      case 'provide_liquidity':
        factors.push({
          name: 'Liquidity Demand',
          weight: 0.1,
          value: this.evaluateLiquidityDemand(marketConditions),
          impact: 'positive'
        });
        break;

      case 'hold':
        factors.push({
          name: 'Market Stability',
          weight: 0.1,
          value: this.evaluateMarketStability(marketConditions),
          impact: 'neutral'
        });
        break;
    }

    return factors;
  }

  private async evaluateFairness(action: string, marketConditions: MarketConditions): Promise<number> {
    // Evaluate if action is fair to all market participants
    // Simplified fairness score based on market impact
    const marketImpact = this.estimateMarketImpact(action, marketConditions);
    return Math.max(0, 1 - marketImpact / 1000000); // Normalize to [0,1]
  }

  private async evaluateMarketManipulationRisk(action: string, marketConditions: MarketConditions): Promise<number> {
    // Evaluate risk of market manipulation
    // Higher risk for large orders that could move prices significantly
    const orderSize = this.estimateOrderSize(action);
    const marketDepth = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);
    
    return Math.min(orderSize / marketDepth, 1);
  }

  private async evaluateConflictOfInterest(action: string, agent: Agent): Promise<number> {
    // Evaluate potential conflicts of interest
    // Simplified based on agent's positions and action
    return 0.1; // Low conflict risk for most actions
  }

  private async evaluateSocialWelfareImpact(action: string, marketConditions: MarketConditions): Promise<number> {
    // Evaluate impact on overall market efficiency and welfare
    const efficiencyGain = this.estimateEfficiencyGain(action, marketConditions);
    return efficiencyGain > 0 ? 0.1 : -0.05;
  }

  private async evaluateTransparency(action: string): Promise<number> {
    // Evaluate how transparent the action is
    // Higher transparency for simpler, more direct actions
    const complexity = this.getActionComplexity(action);
    return Math.max(0, 1 - complexity / 10);
  }

  private calculateFactorConfidence(factors: RationaleFactor[]): number {
    if (factors.length === 0) return 0;
    
    const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0);
    const weightedImpact = factors.reduce((sum, f) => {
      const impactScore = f.impact === 'positive' ? 1 : 
        f.impact === 'negative' ? -1 : 0.5;
      return sum + f.weight * impactScore;
    }, 0);
    
    return (weightedImpact / totalWeight + 1) / 2; // Normalize to [0,1]
  }

  private calculateEthicalConfidence(ethicalConsiderations: EthicalConsideration[]): number {
    if (ethicalConsiderations.length === 0) return 1;
    
    const satisfiedCount = ethicalConsiderations.filter(ec => ec.satisfied).length;
    const totalImpact = ethicalConsiderations.reduce((sum, ec) => sum + ec.impact, 0);
    const averageImpact = totalImpact / ethicalConsiderations.length;
    
    return (satisfiedCount / ethicalConsiderations.length + averageImpact) / 2;
  }

  private calculateDataQualityConfidence(currentState: AgentState): number {
    // Evaluate quality of data used for decision
    let dataQuality = 1.0;
    
    // Reduce confidence for stale data
    const dataAge = Date.now() - currentState.lastAction ? 
      currentState.lastAction.getTime() : Date.now();
    if (dataAge > 300000) { // 5 minutes
      dataQuality -= 0.1;
    }
    
    // Reduce confidence for incomplete data
    if (currentState.positions.length === 0) {
      dataQuality -= 0.2;
    }
    
    return Math.max(0, dataQuality);
  }

  private async validateAlternative(
    alternative: Alternative,
    agent: Agent,
    currentState: AgentState
  ): Promise<{ valid: boolean; reason: string }> {
    // Validate if alternative is feasible and better than current action
    if (alternative.expectedUtility < 0) {
      return {
        valid: false,
        reason: 'Expected utility is negative'
      };
    }
    
    if (alternative.risk > 0.5) {
      return {
        valid: false,
        reason: 'Risk level too high'
      };
    }
    
    return {
      valid: true,
      reason: 'Alternative is valid'
    };
  }

  private async generatePossibleActions(currentState: AgentState, agent: Agent): Promise<string[]> {
    const actions: string[] = [];
    
    // Generate actions based on current state and agent capabilities
    if (this.canBuy(currentState)) {
      actions.push('buy');
    }
    
    if (this.canSell(currentState)) {
      actions.push('sell');
    }
    
    if (this.canProvideLiquidity(currentState)) {
      actions.push('provide_liquidity');
    }
    
    if (this.canBorrow(currentState)) {
      actions.push('borrow');
    }
    
    if (this.canLend(currentState)) {
      actions.push('lend');
    }
    
    actions.push('hold'); // Always an option
    
    return actions;
  }

  private async estimateActionUtility(action: string, currentState: AgentState, agent: Agent): Promise<number> {
    // Simplified utility estimation
    const baseUtility = Math.random() * 0.1;
    
    switch (action.toLowerCase()) {
      case 'buy':
        return baseUtility + 0.05;
      case 'sell':
        return baseUtility + 0.03;
      case 'provide_liquidity':
        return baseUtility + 0.02;
      default:
        return baseUtility;
    }
  }

  private async estimateActionRisk(action: string, currentState: AgentState): Promise<number> {
    // Simplified risk estimation
    return Math.random() * 0.3; // 0-30% risk
  }

  private getDecisionPriorities(agent: Agent): string {
    // Return agent's decision priorities based on utility function
    if (agent.utilityFunction.type === 'profit_maximization') {
      return 'profit maximization and risk management';
    } else if (agent.utilityFunction.type === 'risk_minimization') {
      return 'risk minimization and capital preservation';
    } else {
      return 'balanced utility optimization';
    }
  }

  private evaluateBuyOpportunity(currentState: AgentState, marketConditions: MarketConditions): number {
    // Evaluate if current market conditions present good buying opportunities
    const avgPrice = Object.values(marketConditions.price)
      .reduce((sum, price) => sum + price, 0) / Object.keys(marketConditions.price).length;
    const priceVolatility = this.calculateAverageVolatility(marketConditions);
    
    // Good buying opportunity: prices below average with moderate volatility
    return priceVolatility < 0.2 ? 0.8 : 0.4;
  }

  private evaluateSellPressure(currentState: AgentState, marketConditions: MarketConditions): number {
    // Evaluate current sell pressure in the market
    return 0.5; // Neutral
  }

  private evaluateLiquidityDemand(marketConditions: MarketConditions): number {
    // Evaluate demand for liquidity in current market
    const totalLiquidity = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);
    const totalVolume = Object.values(marketConditions.volume)
      .reduce((sum, vol) => sum + vol, 0);
    
    return totalVolume / totalLiquidity;
  }

  private evaluateMarketStability(marketConditions: MarketConditions): number {
    // Evaluate overall market stability
    const volatility = this.calculateAverageVolatility(marketConditions);
    return Math.max(0, 1 - volatility / 0.5); // Normalize to [0,1]
  }

  private estimateMarketImpact(action: string, marketConditions: MarketConditions): number {
    // Estimate the impact of the action on market prices
    const orderSize = this.estimateOrderSize(action);
    const marketDepth = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);
    
    return orderSize * 1000 / marketDepth; // Simplified impact calculation
  }

  private estimateOrderSize(action: string): number {
    // Estimate the size of the order based on action type
    switch (action.toLowerCase()) {
      case 'buy':
      case 'sell':
        return 10000; // $10,000
      case 'provide_liquidity':
        return 5000; // $5,000
      default:
        return 1000;
    }
  }

  private estimateEfficiencyGain(action: string, marketConditions: MarketConditions): number {
    // Estimate efficiency gain from the action
    return Math.random() * 1000 - 500; // Random efficiency gain/loss
  }

  private getActionComplexity(action: string): number {
    // Return complexity score for the action
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

  private canBuy(currentState: AgentState): boolean {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    return capital > 1000;
  }

  private canSell(currentState: AgentState): boolean {
    return currentState.positions.length > 0;
  }

  private canProvideLiquidity(currentState: AgentState): boolean {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    return capital > 2000;
  }

  private canBorrow(currentState: AgentState): boolean {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    return capital > 500 && currentState.positions.length < 3;
  }

  private canLend(currentState: AgentState): boolean {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    return capital > 5000;
  }

  private async countAlternatives(proposedAction: string): Promise<number> {
    // Count how many alternatives were considered
    return 5; // Placeholder
  }
}
