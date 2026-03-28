import { Injectable, Logger } from '@nestjs/common';
import { 
  SimulationEnvironment,
  Agent,
  AgentState,
  MarketConditions,
  SimulationState,
  Transaction,
  Negotiation,
  Position,
  Resource
} from '../interfaces/agent.interface';

@Injectable()
export class SimulationService {
  private readonly logger = new Logger(SimulationService.name);
  private activeSimulations = new Map<string, SimulationEnvironment>();
  private simulationHistory = new Map<string, SimulationState[]>();

  async createSimulationEnvironment(
    name: string,
    agentIds: string[],
    initialMarketConditions: MarketConditions,
    maxTimeSteps: number = 1000
  ): Promise<SimulationEnvironment> {
    const simulationId = `sim_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Initialize agent states
    const agentStates: { [agentId: string]: AgentState } = {};
    for (const agentId of agentIds) {
      agentStates[agentId] = await this.initializeAgentState(agentId);
    }
    
    const initialState: SimulationState = {
      timeStep: 0,
      agentStates,
      marketState: initialMarketConditions,
      transactions: [],
      negotiations: []
    };
    
    const simulation: SimulationEnvironment = {
      id: simulationId,
      name,
      agents: agentIds,
      marketConditions: initialMarketConditions,
      timeStep: 0,
      maxTimeSteps,
      currentState: initialState,
      history: [initialState]
    };
    
    this.activeSimulations.set(simulationId, simulation);
    this.simulationHistory.set(simulationId, [initialState]);
    
    this.logger.log(`Created simulation environment ${simulationId} with ${agentIds.length} agents`);
    
    return simulation;
  }

  private async initializeAgentState(agentId: string): Promise<AgentState> {
    // This would fetch agent from database
    return {
      resources: [
        {
          id: 'capital_1',
          type: 'capital',
          amount: 10000,
          currency: 'USD',
          availability: 'available'
        }
      ],
      positions: [],
      utility: 0,
      lastAction: 'initialize',
      decisionRationale: {
        primaryFactor: 'Initial state',
        factors: [],
        confidence: 1.0,
        ethicalConsiderations: [],
        alternatives: [],
        reasoning: 'Agent initialized with starting resources and no positions'
      }
    };
  }

  async runSimulation(
    simulationId: string,
    realTime: boolean = false
  ): Promise<SimulationState[]> {
    const simulation = this.activeSimulations.get(simulationId);
    if (!simulation) {
      throw new Error(`Simulation ${simulationId} not found`);
    }

    this.logger.log(`Starting simulation ${simulationId}: ${simulation.name}`);
    
    const history: SimulationState[] = [];
    let currentState = { ...simulation.currentState };
    
    for (let timeStep = 1; timeStep <= simulation.maxTimeSteps; timeStep++) {
      // Update market conditions
      const newMarketConditions = await this.updateMarketConditions(
        currentState.marketState,
        timeStep
      );
      
      // Process agent decisions
      const newAgentStates = await this.processAgentDecisions(
        currentState.agentStates,
        newMarketConditions,
        simulationId
      );
      
      // Execute transactions and negotiations
      const { transactions, negotiations } = await this.executeAgentActions(
        newAgentStates,
        newMarketConditions
      );
      
      // Create new simulation state
      const newState: SimulationState = {
        timeStep,
        agentStates: newAgentStates,
        marketState: newMarketConditions,
        transactions,
        negotiations
      };
      
      currentState = newState;
      history.push(newState);
      
      // Update simulation
      simulation.timeStep = timeStep;
      simulation.currentState = newState;
      simulation.marketConditions = newMarketConditions;
      simulation.history = [...simulation.history, newState];
      
      // Real-time update
      if (realTime) {
        await this.delay(100); // 100ms per timestep for real-time simulation
        this.broadcastSimulationUpdate(simulationId, newState);
      }
      
      // Check for simulation end conditions
      if (await this.checkSimulationEndConditions(simulation, newState)) {
        this.logger.log(`Simulation ${simulationId} ended at timestep ${timeStep}`);
        break;
      }
    }
    
    // Store final history
    this.simulationHistory.set(simulationId, history);
    
    // Clean up
    this.activeSimulations.delete(simulationId);
    
    return history;
  }

  private async updateMarketConditions(
    currentConditions: MarketConditions,
    timeStep: number
  ): Promise<MarketConditions> {
    // Simulate market dynamics
    const newConditions = { ...currentConditions };
    
    // Price dynamics (random walk with trend)
    for (const asset in newConditions.price) {
      const trend = Math.sin(timeStep * 0.1) * 0.02; // Cyclical trend
      const noise = (Math.random() - 0.5) * 0.01; // Random noise
      const change = trend + noise;
      
      newConditions.price[asset] *= (1 + change);
      newConditions.price[asset] = Math.max(newConditions.price[asset], 0.01); // Minimum price
    }
    
    // Volatility dynamics
    for (const asset in newConditions.volatility) {
      const baseVolatility = 0.2;
      const volatilityChange = (Math.random() - 0.5) * 0.02;
      newConditions.volatility[asset] = Math.max(
        baseVolatility + volatilityChange,
        0.05
      );
    }
    
    // Volume dynamics
    for (const asset in newConditions.volume) {
      const baseVolume = 1000000;
      const volumeChange = Math.sin(timeStep * 0.05) * 0.3 + 1;
      newConditions.volume[asset] = baseVolume * volumeChange;
    }
    
    // Liquidity dynamics
    for (const asset in newConditions.liquidity) {
      const baseLiquidity = 500000;
      const liquidityChange = Math.cos(timeStep * 0.03) * 0.2 + 1;
      newConditions.liquidity[asset] = baseLiquidity * liquidityChange;
    }
    
    // Interest rates (slowly changing)
    for (const currency in newConditions.interestRates) {
      const baseRate = 0.05;
      const rateChange = Math.sin(timeStep * 0.01) * 0.002;
      newConditions.interestRates[currency] = Math.max(
        baseRate + rateChange,
        0
      );
    }
    
    return newConditions;
  }

  private async processAgentDecisions(
    agentStates: { [agentId: string]: AgentState },
    marketConditions: MarketConditions,
    simulationId: string
  ): Promise<{ [agentId: string]: AgentState }> {
    const newAgentStates: { [agentId: string]: AgentState } = {};
    
    for (const [agentId, currentState] of Object.entries(agentStates)) {
      try {
        // Get agent's decision
        const decision = await this.makeAgentDecision(
          agentId,
          currentState,
          marketConditions,
          simulationId
        );
        
        // Apply decision to agent state
        const newState = await this.applyAgentDecision(
          currentState,
          decision,
          marketConditions
        );
        
        newAgentStates[agentId] = newState;
      } catch (error) {
        this.logger.error(`Error processing decision for agent ${agentId}:`, error);
        newAgentStates[agentId] = currentState; // Keep current state on error
      }
    }
    
    return newAgentStates;
  }

  private async makeAgentDecision(
    agentId: string,
    currentState: AgentState,
    marketConditions: MarketConditions,
    simulationId: string
  ): Promise<string> {
    // This would integrate with agent's decision-making logic
    // For now, implement a simple rule-based decision
    
    const totalCapital = currentState.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    
    const hasPositions = currentState.positions.length > 0;
    
    // Simple decision logic
    if (totalCapital > 5000 && !hasPositions) {
      return 'buy';
    } else if (hasPositions && this.shouldSell(currentState, marketConditions)) {
      return 'sell';
    } else if (totalCapital > 1000) {
      return 'provide_liquidity';
    } else {
      return 'hold';
    }
  }

  private shouldSell(currentState: AgentState, marketConditions: MarketConditions): boolean {
    // Check if any position is profitable
    return currentState.positions.some(position => {
      const profitPercent = (position.currentPrice - position.entryPrice) / position.entryPrice;
      return profitPercent > 0.05; // Sell if 5% profit
    });
  }

  private async applyAgentDecision(
    currentState: AgentState,
    decision: string,
    marketConditions: MarketConditions
  ): Promise<AgentState> {
    const newState: AgentState = {
      ...currentState,
      lastAction: decision,
      decisionRationale: {
        primaryFactor: 'Market analysis',
        factors: [
          {
            name: 'Capital availability',
            weight: 0.3,
            value: currentState.resources[0]?.amount || 0,
            impact: 'positive'
          },
          {
            name: 'Market conditions',
            weight: 0.4,
            value: Object.values(marketConditions.price).reduce((a, b) => a + b, 0),
            impact: 'neutral'
          },
          {
            name: 'Position status',
            weight: 0.3,
            value: currentState.positions.length,
            impact: currentState.positions.length > 0 ? 'negative' : 'neutral'
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
        alternatives: [
          {
            description: 'Wait for better conditions',
            expectedUtility: 0.1,
            risk: 0.05,
            rejected: false,
            reason: 'Current decision is optimal'
          }
        ],
        reasoning: `Decision to ${decision} based on current capital, market conditions, and existing positions.`
      }
    };
    
    // Apply decision effects
    switch (decision) {
      case 'buy':
        newState = await this.executeBuy(newState, marketConditions);
        break;
      
      case 'sell':
        newState = await this.executeSell(newState, marketConditions);
        break;
      
      case 'provide_liquidity':
        newState = await this.executeProvideLiquidity(newState, marketConditions);
        break;
      
      case 'hold':
        // No change in state
        break;
    }
    
    return newState;
  }

  private async executeBuy(
    state: AgentState,
    marketConditions: MarketConditions
  ): Promise<AgentState> {
    const capitalResource = state.resources.find(r => r.type === 'capital');
    if (!capitalResource || capitalResource.amount < 1000) {
      return state;
    }
    
    // Buy ETH with USD
    const ethPrice = marketConditions.price['ETH'] || 2000;
    const buyAmount = Math.min(capitalResource.amount * 0.5, 5000); // Buy with 50% of capital, max $5000
    const ethAmount = buyAmount / ethPrice;
    
    const newPosition: Position = {
      id: `pos_${Date.now()}`,
      asset: 'ETH',
      amount: ethAmount,
      entryPrice: ethPrice,
      currentPrice: ethPrice,
      unrealizedPnL: 0,
      realizedPnL: 0,
      timestamp: new Date()
    };
    
    // Update resources
    const updatedResources = state.resources.map(r => {
      if (r.id === capitalResource.id) {
        return { ...r, amount: r.amount - buyAmount };
      }
      return r;
    });
    
    // Add ETH resource
    updatedResources.push({
      id: `eth_${Date.now()}`,
      type: 'token',
      amount: ethAmount,
      currency: 'ETH',
      availability: 'available'
    });
    
    return {
      ...state,
      resources: updatedResources,
      positions: [...state.positions, newPosition],
      utility: state.utility + Math.random() * 0.1 // Small utility gain
    };
  }

  private async executeSell(
    state: AgentState,
    marketConditions: MarketConditions
  ): Promise<AgentState> {
    const ethResource = state.resources.find(r => r.type === 'token' && r.currency === 'ETH');
    if (!ethResource || ethResource.amount < 0.1) {
      return state;
    }
    
    // Sell ETH for USD
    const ethPrice = marketConditions.price['ETH'] || 2000;
    const sellAmount = Math.min(ethResource.amount * 0.5, ethResource.amount); // Sell 50%
    const usdAmount = sellAmount * ethPrice;
    
    // Update position
    const updatedPositions = state.positions.map(pos => {
      if (pos.asset === 'ETH') {
        const realizedPnL = (ethPrice - pos.entryPrice) * sellAmount;
        return {
          ...pos,
          currentPrice: ethPrice,
          amount: pos.amount - sellAmount,
          realizedPnL: pos.realizedPnL + realizedPnL,
          unrealizedPnL: pos.unrealizedPnL + (ethPrice - pos.currentPrice) * (pos.amount - sellAmount)
        };
      }
      return pos;
    });
    
    // Update resources
    const updatedResources = state.resources.map(r => {
      if (r.id === ethResource.id) {
        return { ...r, amount: r.amount - sellAmount };
      }
      if (r.type === 'capital') {
        return { ...r, amount: r.amount + usdAmount };
      }
      return r;
    });
    
    return {
      ...state,
      resources: updatedResources,
      positions: updatedPositions,
      utility: state.utility + Math.random() * 0.15
    };
  }

  private async executeProvideLiquidity(
    state: AgentState,
    marketConditions: MarketConditions
  ): Promise<AgentState> {
    const capitalResource = state.resources.find(r => r.type === 'capital');
    if (!capitalResource || capitalResource.amount < 2000) {
      return state;
    }
    
    // Provide liquidity to ETH/USDC pool
    const liquidityAmount = Math.min(capitalResource.amount * 0.3, 3000);
    const ethAmount = liquidityAmount / 2;
    const usdcAmount = liquidityAmount / 2;
    
    // Create liquidity position
    const liquidityPosition: Position = {
      id: `liq_${Date.now()}`,
      asset: 'ETH/USDC',
      amount: liquidityAmount,
      entryPrice: 1,
      currentPrice: 1,
      unrealizedPnL: 0,
      realizedPnL: 0,
      timestamp: new Date()
    };
    
    // Update resources
    const updatedResources = state.resources.map(r => {
      if (r.id === capitalResource.id) {
        return { ...r, amount: r.amount - liquidityAmount, availability: 'locked' };
      }
      return r;
    });
    
    // Add liquidity position resource
    updatedResources.push({
      id: `liq_pos_${Date.now()}`,
      type: 'liquidity_position',
      amount: liquidityAmount,
      currency: 'USD',
      availability: 'staked'
    });
    
    return {
      ...state,
      resources: updatedResources,
      positions: [...state.positions, liquidityPosition],
      utility: state.utility + 0.05 // Liquidity provision utility
    };
  }

  private async executeAgentActions(
    agentStates: { [agentId: string]: AgentState },
    marketConditions: MarketConditions
  ): Promise<{ transactions: Transaction[]; negotiations: Negotiation[] }> {
    const transactions: Transaction[] = [];
    const negotiations: Negotiation[] = [];
    
    // Process agent actions into transactions
    for (const [agentId, state] of Object.entries(agentStates)) {
      if (state.lastAction === 'buy' || state.lastAction === 'sell') {
        const transaction: Transaction = {
          id: `tx_${Date.now()}_${agentId}`,
          type: 'trade',
          participants: [agentId],
          terms: {
            asset: state.lastAction === 'buy' ? 'ETH' : 'ETH',
            quantity: 1,
            price: marketConditions.price['ETH'] || 2000,
            currency: 'USD'
          },
          executionPrice: marketConditions.price['ETH'] || 2000,
          timestamp: new Date(),
          status: 'confirmed'
        };
        
        transactions.push(transaction);
      }
    }
    
    return { transactions, negotiations };
  }

  private async checkSimulationEndConditions(
    simulation: SimulationEnvironment,
    currentState: SimulationState
  ): Promise<boolean> {
    // Check if any agent is out of capital
    for (const [agentId, state] of Object.entries(currentState.agentStates)) {
      const capital = state.resources
        .filter(r => r.type === 'capital')
        .reduce((sum, r) => sum + r.amount, 0);
      
      if (capital < 100) {
        this.logger.log(`Agent ${agentId} out of capital, ending simulation`);
        return true;
      }
    }
    
    // Check if max time steps reached
    if (currentState.timeStep >= simulation.maxTimeSteps) {
      return true;
    }
    
    // Check for market crash
    const totalMarketValue = Object.values(currentState.marketState.price)
      .reduce((sum, price) => sum + price, 0);
    
    if (totalMarketValue < 1000) {
      this.logger.log('Market crash detected, ending simulation');
      return true;
    }
    
    return false;
  }

  private async delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private broadcastSimulationUpdate(simulationId: string, state: SimulationState): void {
    // This would broadcast via WebSocket or other real-time communication
    this.logger.log(`Simulation ${simulationId} update: timestep ${state.timeStep}`);
  }

  getSimulationHistory(simulationId: string): SimulationState[] {
    return this.simulationHistory.get(simulationId) || [];
  }

  getActiveSimulations(): SimulationEnvironment[] {
    return Array.from(this.activeSimulations.values());
  }

  async pauseSimulation(simulationId: string): Promise<void> {
    const simulation = this.activeSimulations.get(simulationId);
    if (simulation) {
      simulation.timeStep = -1; // Use -1 to indicate paused
      this.logger.log(`Simulation ${simulationId} paused`);
    }
  }

  async resumeSimulation(simulationId: string): Promise<void> {
    const simulation = this.activeSimulations.get(simulationId);
    if (simulation && simulation.timeStep === -1) {
      simulation.timeStep = simulation.currentState.timeStep;
      this.logger.log(`Simulation ${simulationId} resumed`);
    }
  }

  async stopSimulation(simulationId: string): Promise<void> {
    const simulation = this.activeSimulations.get(simulationId);
    if (simulation) {
      this.simulationHistory.set(simulationId, simulation.history);
      this.activeSimulations.delete(simulationId);
      this.logger.log(`Simulation ${simulationId} stopped`);
    }
  }

  getSimulationMetrics(simulationId: string): {
    totalTransactions: number;
    totalVolume: number;
    averageUtility: number;
    finalCapitalDistribution: { [agentId: string]: number };
  } | null {
    const history = this.simulationHistory.get(simulationId);
    if (!history || history.length === 0) return null;
    
    const finalState = history[history.length - 1];
    const allTransactions = history.flatMap(state => state.transactions);
    
    const totalTransactions = allTransactions.length;
    const totalVolume = allTransactions.reduce((sum, tx) => 
      sum + (tx.terms.quantity * tx.executionPrice), 0
    );
    
    const averageUtility = Object.values(finalState.agentStates)
      .reduce((sum, state) => sum + state.utility, 0) / 
      Object.keys(finalState.agentStates).length;
    
    const finalCapitalDistribution: { [agentId: string]: number } = {};
    for (const [agentId, state] of Object.entries(finalState.agentStates)) {
      const capital = state.resources
        .filter(r => r.type === 'capital')
        .reduce((sum, r) => sum + r.amount, 0);
      finalCapitalDistribution[agentId] = capital;
    }
    
    return {
      totalTransactions,
      totalVolume,
      averageUtility,
      finalCapitalDistribution
    };
  }
}
