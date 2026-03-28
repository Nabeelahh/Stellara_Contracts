import { Injectable, Logger } from '@nestjs/common';
import { 
  Agent,
  AgentState,
  MarketConditions,
  UtilityFunction,
  RLModel,
  SimulationEnvironment,
  Negotiation,
  EthicalConsideration
} from '../interfaces/agent.interface';

@Injectable()
export class AutonomousAgentService {
  private readonly logger = new Logger(AutonomousAgentService.name);
  private agents = new Map<string, Agent>();
  private agentStates = new Map<string, AgentState>();

  async createAgent(
    name: string,
    type: any,
    utilityFunction: UtilityFunction,
    initialResources: any[],
    config: any
  ): Promise<Agent> {
    const agent: Agent = {
      id: `agent_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name,
      type,
      status: 'active',
      utilityFunction,
      strategies: [],
      resources: initialResources,
      constraints: [],
      reputation: 0.5,
      createdAt: new Date(),
      lastActive: new Date()
    };

    this.agents.set(agent.id, agent);
    
    // Initialize agent state
    const agentState: AgentState = {
      resources: initialResources,
      positions: [],
      utility: 0,
      lastAction: 'initialize',
      decisionRationale: {
        primaryFactor: 'Agent initialization',
        factors: [],
        confidence: 1.0,
        ethicalConsiderations: [],
        alternatives: [],
        reasoning: `Agent ${name} initialized with utility function ${utilityFunction.type}`
      }
    };

    this.agentStates.set(agent.id, agentState);

    this.logger.log(`Created autonomous agent ${agent.id} (${name}) with type ${type}`);
    
    return agent;
  }

  async makeDecision(
    agentId: string,
    marketConditions: MarketConditions,
    availableActions: string[]
  ): Promise<{
    action: string;
    confidence: number;
    rationale: any;
  }> {
    const agent = this.agents.get(agentId);
    const currentState = this.agentStates.get(agentId);
    
    if (!agent || !currentState) {
      throw new Error(`Agent ${agentId} not found`);
    }

    this.logger.log(`Making decision for agent ${agentId}`);

    // Evaluate utility for each available action
    const actionEvaluations = await Promise.all(
      availableActions.map(async action => ({
        action,
        utility: await this.evaluateActionUtility(agent, currentState, action, marketConditions),
        risk: await this.evaluateActionRisk(action, marketConditions),
        ethicalScore: await this.evaluateActionEthics(agent, action, marketConditions)
      }))
    );

    // Select best action based on utility, risk, and ethics
    const bestAction = this.selectBestAction(actionEvaluations, agent.utilityFunction);

    // Generate decision rationale
    const rationale = await this.generateDecisionRationale(
      agent,
      currentState,
      bestAction.action,
      marketConditions,
      actionEvaluations.map(ae => ({
        description: `Alternative: ${ae.action}`,
        expectedUtility: ae.utility,
        risk: ae.risk,
        rejected: ae.action !== bestAction.action,
        reason: ae.action === bestAction.action ? 'Selected action' : 'Lower utility'
      }))
    );

    return {
      action: bestAction.action,
      confidence: bestAction.confidence,
      rationale
    };
  }

  async executeAction(
    agentId: string,
    action: string,
    marketConditions: MarketConditions
  ): Promise<{
    success: boolean;
    newState: AgentState;
    executionDetails: any;
  }> {
    const agent = this.agents.get(agentId);
    const currentState = this.agentStates.get(agentId);
    
    if (!agent || !currentState) {
      throw new Error(`Agent ${agentId} not found`);
    }

    this.logger.log(`Executing action ${action} for agent ${agentId}`);

    try {
      // Execute the action
      const executionResult = await this.performAction(agent, currentState, action, marketConditions);
      
      // Update agent state
      const newState = await this.updateAgentState(currentState, action, executionResult);
      this.agentStates.set(agentId, newState);

      // Update agent last active time
      agent.lastActive = new Date();

      return {
        success: true,
        newState,
        executionDetails: executionResult
      };
    } catch (error) {
      this.logger.error(`Failed to execute action ${action} for agent ${agentId}:`, error);
      
      return {
        success: false,
        newState: currentState,
        executionDetails: { error: error.message }
      };
    }
  }

  async negotiate(
    agentId: string,
    counterpartyId: string,
    terms: any,
    protocol: string
  ): Promise<{
    success: boolean;
    result?: any;
  }> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    this.logger.log(`Agent ${agentId} initiating negotiation with ${counterpartyId}`);

    // This would integrate with negotiation service
    // For now, return a mock negotiation result
    const negotiationResult = {
      accepted: Math.random() > 0.3,
      finalTerms: terms,
      confidence: 0.8
    };

    return {
      success: negotiationResult.accepted,
      result: negotiationResult
    };
  }

  async learn(
    agentId: string,
    experience: any
  ): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    this.logger.log(`Agent ${agentId} learning from experience`);

    // This would integrate with reinforcement learning service
    // Update agent's strategy based on experience
    agent.strategies = await this.updateStrategies(agent.strategies, experience);
  }

  private async evaluateActionUtility(
    agent: Agent,
    currentState: AgentState,
    action: string,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Simplified utility calculation
    let utility = 0;

    switch (agent.utilityFunction.type) {
      case 'profit_maximization':
        utility = await this.calculateProfitUtility(action, currentState, marketConditions);
        break;
      
      case 'risk_minimization':
        utility = await this.calculateRiskUtility(action, currentState, marketConditions);
        break;
      
      case 'utility_maximization':
        utility = await this.calculateWeightedUtility(agent, action, currentState, marketConditions);
        break;
      
      default:
        utility = Math.random() * 0.1; // Random utility for unknown types
    }

    return utility;
  }

  private async evaluateActionRisk(
    action: string,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Calculate risk score for the action
    const volatility = Object.values(marketConditions.volatility)
      .reduce((sum, vol) => sum + vol, 0) / Object.keys(marketConditions.volatility).length;
    
    let risk = volatility * 0.5;
    
    // Adjust risk based on action type
    switch (action.toLowerCase()) {
      case 'buy':
      case 'sell':
        risk += 0.1;
        break;
      case 'provide_liquidity':
        risk -= 0.05;
        break;
      case 'hold':
        risk -= 0.1;
        break;
    }

    return Math.min(Math.max(risk, 0), 1);
  }

  private async evaluateActionEthics(
    agent: Agent,
    action: string,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Evaluate ethical considerations
    let ethicalScore = 0.8; // Base score

    // Check for market manipulation potential
    const manipulationRisk = await this.checkManipulationRisk(action, marketConditions);
    ethicalScore -= manipulationRisk * 0.3;

    // Check for fairness
    const fairnessScore = await this.checkFairness(action, marketConditions);
    ethicalScore += fairnessScore * 0.2;

    return Math.min(Math.max(ethicalScore, 0), 1);
  }

  private selectBestAction(
    actionEvaluations: any[],
    utilityFunction: UtilityFunction
  ): { action: string; confidence: number } {
    // Sort by utility, risk, and ethics
    const sortedActions = actionEvaluations.sort((a, b) => {
      // Primary sort by utility
      if (utilityFunction.type === 'profit_maximization') {
        return b.utility - a.utility;
      } else if (utilityFunction.type === 'risk_minimization') {
        return a.risk - b.risk;
      } else {
        // Weighted combination
        const scoreA = a.utility * 0.6 - a.risk * 0.3 + a.ethicalScore * 0.1;
        const scoreB = b.utility * 0.6 - b.risk * 0.3 + b.ethicalScore * 0.1;
        return scoreB - scoreA;
      }
    });

    const bestAction = sortedActions[0];
    
    // Calculate confidence based on how much better it is than alternatives
    const secondBest = sortedActions[1];
    let confidence = 0.5;
    
    if (secondBest) {
      const improvement = bestAction.utility - secondBest.utility;
      confidence = Math.min(0.9, 0.5 + improvement);
    }

    return {
      action: bestAction.action,
      confidence
    };
  }

  private async performAction(
    agent: Agent,
    currentState: AgentState,
    action: string,
    marketConditions: MarketConditions
  ): Promise<any> {
    switch (action.toLowerCase()) {
      case 'buy':
        return this.executeBuy(agent, currentState, marketConditions);
      
      case 'sell':
        return this.executeSell(agent, currentState, marketConditions);
      
      case 'provide_liquidity':
        return this.executeProvideLiquidity(agent, currentState, marketConditions);
      
      case 'borrow':
        return this.executeBorrow(agent, currentState, marketConditions);
      
      case 'lend':
        return this.executeLend(agent, currentState, marketConditions);
      
      case 'hold':
        return this.executeHold(agent, currentState);
      
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  private async executeBuy(
    agent: Agent,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<any> {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    
    if (capital < 1000) {
      throw new Error('Insufficient capital to buy');
    }

    const assetPrice = marketConditions.price['ETH'] || 2000;
    const buyAmount = Math.min(capital * 0.5, 5000);
    const assetAmount = buyAmount / assetPrice;

    return {
      type: 'buy',
      asset: 'ETH',
      amount: assetAmount,
      price: assetPrice,
      cost: buyAmount,
      success: true,
      timestamp: new Date()
    };
  }

  private async executeSell(
    agent: Agent,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<any> {
    const ethPosition = currentState.positions.find(p => p.asset === 'ETH');
    if (!ethPosition || ethPosition.amount <= 0) {
      throw new Error('No ETH position to sell');
    }

    const assetPrice = marketConditions.price['ETH'] || 2000;
    const sellAmount = Math.min(ethPosition.amount * 0.5, ethPosition.amount);
    const revenue = sellAmount * assetPrice;

    return {
      type: 'sell',
      asset: 'ETH',
      amount: sellAmount,
      price: assetPrice,
      revenue: revenue,
      success: true,
      timestamp: new Date()
    };
  }

  private async executeProvideLiquidity(
    agent: Agent,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<any> {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    
    if (capital < 2000) {
      throw new Error('Insufficient capital to provide liquidity');
    }

    const liquidityAmount = Math.min(capital * 0.3, 3000);

    return {
      type: 'provide_liquidity',
      asset: 'ETH/USDC',
      amount: liquidityAmount,
      success: true,
      timestamp: new Date()
    };
  }

  private async executeBorrow(
    agent: Agent,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<any> {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    
    if (capital < 500) {
      throw new Error('Insufficient collateral to borrow');
    }

    const borrowAmount = Math.min(capital * 2, 10000);
    const interestRate = marketConditions.interestRates['USDC'] || 0.05;

    return {
      type: 'borrow',
      asset: 'USDC',
      amount: borrowAmount,
      interestRate: interestRate,
      success: true,
      timestamp: new Date()
    };
  }

  private async executeLend(
    agent: Agent,
    currentState: AgentState,
    marketConditions: MarketConditions
  ): Promise<any> {
    const capital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    
    if (capital < 5000) {
      throw new Error('Insufficient capital to lend');
    }

    const lendAmount = Math.min(capital * 0.4, 8000);
    const interestRate = marketConditions.interestRates['USDC'] || 0.05;

    return {
      type: 'lend',
      asset: 'USDC',
      amount: lendAmount,
      interestRate: interestRate,
      success: true,
      timestamp: new Date()
    };
  }

  private async executeHold(
    agent: Agent,
    currentState: AgentState
  ): Promise<any> {
    return {
      type: 'hold',
      success: true,
      timestamp: new Date()
    };
  }

  private async updateAgentState(
    currentState: AgentState,
    action: string,
    executionResult: any
  ): Promise<AgentState> {
    const newState = { ...currentState };

    // Update resources based on action
    if (executionResult.type === 'buy') {
      const capitalResource = newState.resources.find(r => r.type === 'capital');
      if (capitalResource) {
        capitalResource.amount -= executionResult.cost;
      }
      
      // Add asset position
      newState.positions.push({
        id: `pos_${Date.now()}`,
        asset: executionResult.asset,
        amount: executionResult.amount,
        entryPrice: executionResult.price,
        currentPrice: executionResult.price,
        unrealizedPnL: 0,
        realizedPnL: 0,
        timestamp: new Date()
      });
    } else if (executionResult.type === 'sell') {
      // Update position
      const position = newState.positions.find(p => p.asset === executionResult.asset);
      if (position) {
        position.amount -= executionResult.amount;
        position.realizedPnL += (executionResult.price - position.entryPrice) * executionResult.amount;
        position.unrealizedPnL = (executionResult.price - position.entryPrice) * position.amount;
      }
      
      // Add capital
      const capitalResource = newState.resources.find(r => r.type === 'capital');
      if (capitalResource) {
        capitalResource.amount += executionResult.revenue;
      }
    }

    // Update utility
    newState.utility = await this.calculateStateUtility(newState);
    newState.lastAction = action;

    return newState;
  }

  private async calculateStateUtility(state: AgentState): Promise<number> {
    // Calculate total utility of current state
    let utility = 0;

    // Utility from positions
    for (const position of state.positions) {
      utility += position.unrealizedPnL + position.realizedPnL;
    }

    // Utility from resources
    for (const resource of state.resources) {
      if (resource.type === 'capital') {
        utility += resource.amount * 0.001; // Small utility for holding capital
      }
    }

    return utility;
  }

  private async updateStrategies(
    currentStrategies: any[],
    experience: any
  ): Promise<any[]> {
    // Update agent strategies based on experience
    // For now, return current strategies
    return currentStrategies;
  }

  private async checkManipulationRisk(
    action: string,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Simplified manipulation risk check
    return Math.random() * 0.2; // 0-20% risk
  }

  private async checkFairness(
    action: string,
    marketConditions: MarketConditions
  ): Promise<number> {
    // Simplified fairness check
    return 0.8; // High fairness
  }

  private async generateDecisionRationale(
    agent: Agent,
    currentState: AgentState,
    selectedAction: string,
    marketConditions: MarketConditions,
    alternatives: any[]
  ): Promise<any> {
    return {
      primaryFactor: 'Utility maximization',
      factors: [
        {
          name: 'Expected utility',
          weight: 0.6,
          value: Math.random() * 0.1,
          impact: 'positive'
        },
        {
          name: 'Risk assessment',
          weight: 0.3,
          value: Math.random() * 0.3,
          impact: 'neutral'
        },
        {
          name: 'Ethical considerations',
          weight: 0.1,
          value: 0.8,
          impact: 'positive'
        }
      ],
      confidence: 0.75,
      ethicalConsiderations: [
        {
          type: 'fairness',
          constraint: 'No market manipulation',
          satisfied: true,
          impact: 0.9
        }
      ],
      alternatives,
      reasoning: `Agent ${agent.name} selected ${selectedAction} based on utility maximization while considering risk and ethical constraints.`
    };
  }

  getAgent(agentId: string): Agent | null {
    return this.agents.get(agentId) || null;
  }

  getAgentState(agentId: string): AgentState | null {
    return this.agentStates.get(agentId) || null;
  }

  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  async updateAgentReputation(agentId: string, reputationChange: number): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    agent.reputation = Math.max(0, Math.min(1, agent.reputation + reputationChange));
    this.logger.log(`Updated agent ${agentId} reputation to ${agent.reputation}`);
  }

  async deactivateAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    agent.status = 'inactive';
    this.logger.log(`Deactivated agent ${agentId}`);
  }

  async reactivateAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    agent.status = 'active';
    agent.lastActive = new Date();
    this.logger.log(`Reactivated agent ${agentId}`);
  }
}
