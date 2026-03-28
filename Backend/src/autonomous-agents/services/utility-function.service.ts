import { Injectable, Logger } from '@nestjs/common';
import { 
  UtilityFunction, 
  UtilityParameter, 
  UtilityType, 
  OptimizationTarget,
  ParameterType,
  UtilityConstraint,
  ConstraintType,
  Agent,
  AgentState,
  Position,
  MarketConditions
} from '../interfaces/agent.interface';

@Injectable()
export class UtilityFunctionService {
  private readonly logger = new Logger(UtilityFunctionService.name);

  calculateUtility(
    agent: Agent, 
    state: AgentState, 
    marketConditions: MarketConditions
  ): number {
    try {
      const utilityFunction = agent.utilityFunction;
      const parameterValues = this.extractParameterValues(state, marketConditions);
      
      switch (utilityFunction.type) {
        case UtilityType.PROFIT_MAXIMIZATION:
          return this.calculateProfitUtility(utilityFunction, parameterValues);
        
        case UtilityType.RISK_MINIMIZATION:
          return this.calculateRiskUtility(utilityFunction, parameterValues);
        
        case UtilityType.UTILITY_MAXIMIZATION:
          return this.calculateWeightedUtility(utilityFunction, parameterValues);
        
        case UtilityType.SHARPE_RATIO:
          return this.calculateSharpeRatio(utilityFunction, parameterValues);
        
        case UtilityType.SORTINO_RATIO:
          return this.calculateSortinoRatio(utilityFunction, parameterValues);
        
        case UtilityType.CUSTOM:
          return this.calculateCustomUtility(utilityFunction, parameterValues);
        
        default:
          throw new Error(`Unsupported utility function type: ${utilityFunction.type}`);
      }
    } catch (error) {
      this.logger.error(`Failed to calculate utility for agent ${agent.id}:`, error);
      return 0;
    }
  }

  private extractParameterValues(state: AgentState, marketConditions: MarketConditions): { [key: string]: number } {
    const values: { [key: string]: number } = {};
    
    // Extract profit from positions
    const totalPnL = state.positions.reduce((sum, pos) => sum + pos.unrealizedPnL + pos.realizedPnL, 0);
    values[ParameterType.PROFIT] = totalPnL;
    
    // Extract risk from position volatility
    const portfolioVolatility = this.calculatePortfolioVolatility(state.positions, marketConditions);
    values[ParameterType.RISK] = portfolioVolatility;
    
    // Extract total volume
    const totalVolume = state.positions.reduce((sum, pos) => sum + Math.abs(pos.amount), 0);
    values[ParameterType.VOLUME] = totalVolume;
    
    // Extract market volatility
    const avgMarketVolatility = Object.values(marketConditions.volatility)
      .reduce((sum, vol) => sum + vol, 0) / Object.keys(marketConditions.volatility).length;
    values[ParameterType.VOLATILITY] = avgMarketVolatility;
    
    // Extract liquidity
    const totalLiquidity = Object.values(marketConditions.liquidity)
      .reduce((sum, liq) => sum + liq, 0);
    values[ParameterType.LIQUIDITY] = totalLiquidity;
    
    // Extract capital
    const totalCapital = state.resources
      .filter(r => r.type === 'capital')
      .reduce((sum, r) => sum + r.amount, 0);
    values[ParameterType.CAPITAL] = totalCapital;
    
    return values;
  }

  private calculateProfitUtility(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    const profit = parameterValues[ParameterType.PROFIT] || 0;
    const risk = parameterValues[ParameterType.RISK] || 0;
    
    // Apply risk penalty if risk constraint exists
    const riskConstraint = utilityFunction.constraints.find(c => c.type === ConstraintType.MAX_RISK);
    let riskPenalty = 0;
    if (riskConstraint && risk > riskConstraint.value) {
      riskPenalty = (risk - riskConstraint.value) * 10; // Heavy penalty for exceeding risk
    }
    
    return profit - riskPenalty;
  }

  private calculateRiskUtility(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    const risk = parameterValues[ParameterType.RISK] || 0;
    const profit = parameterValues[ParameterType.PROFIT] || 0;
    
    // Minimize risk while maintaining minimum profit
    const minReturnConstraint = utilityFunction.constraints.find(c => c.type === ConstraintType.MIN_RETURN);
    if (minReturnConstraint && profit < minReturnConstraint.value) {
      return -Infinity; // Reject if minimum return not met
    }
    
    return -risk; // Negative because we want to minimize risk
  }

  private calculateWeightedUtility(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    let totalUtility = 0;
    
    for (let i = 0; i < utilityFunction.parameters.length; i++) {
      const param = utilityFunction.parameters[i];
      const weight = utilityFunction.weights[i] || 1;
      const value = parameterValues[param.name] || 0;
      
      // Normalize parameter value to [0, 1] range
      const normalizedValue = this.normalizeParameterValue(param, value);
      totalUtility += normalizedValue * weight;
    }
    
    return totalUtility;
  }

  private calculateSharpeRatio(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    const profit = parameterValues[ParameterType.PROFIT] || 0;
    const risk = parameterValues[ParameterType.RISK] || 0.001; // Avoid division by zero
    const riskFreeRate = 0.02; // 2% risk-free rate
    
    return (profit - riskFreeRate) / risk;
  }

  private calculateSortinoRatio(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    const profit = parameterValues[ParameterType.PROFIT] || 0;
    const risk = parameterValues[ParameterType.RISK] || 0.001;
    const riskFreeRate = 0.02;
    
    // Sortino ratio only considers downside risk
    const downsideRisk = Math.max(0, risk);
    return (profit - riskFreeRate) / downsideRisk;
  }

  private calculateCustomUtility(utilityFunction: UtilityFunction, parameterValues: { [key: string]: number }): number {
    // For custom utility functions, allow JavaScript evaluation (with safety checks)
    try {
      // This would typically use a safe expression evaluator
      // For now, implement a basic weighted sum
      return this.calculateWeightedUtility(utilityFunction, parameterValues);
    } catch (error) {
      this.logger.error('Failed to evaluate custom utility function:', error);
      return 0;
    }
  }

  private normalizeParameterValue(param: UtilityParameter, value: number): number {
    if (param.min !== undefined && param.max !== undefined) {
      return (value - param.min) / (param.max - param.min);
    }
    
    // Apply common normalizations based on parameter type
    switch (param.name) {
      case ParameterType.PROFIT:
        return Math.tanh(value / 10000); // Normalize profit to [-1, 1]
      
      case ParameterType.RISK:
        return 1 - Math.exp(-value / 0.1); // Normalize risk to [0, 1]
      
      case ParameterType.VOLATILITY:
        return Math.min(value / 1, 1); // Normalize volatility to [0, 1]
      
      default:
        return value;
    }
  }

  private calculatePortfolioVolatility(positions: Position[], marketConditions: MarketConditions): number {
    if (positions.length === 0) return 0;
    
    let portfolioVariance = 0;
    const totalValue = positions.reduce((sum, pos) => sum + Math.abs(pos.amount * pos.currentPrice), 0);
    
    for (const position of positions) {
      const weight = (Math.abs(position.amount * position.currentPrice)) / totalValue;
      const assetVolatility = marketConditions.volatility[position.asset] || 0;
      portfolioVariance += Math.pow(weight * assetVolatility, 2);
    }
    
    return Math.sqrt(portfolioVariance);
  }

  optimizeUtility(
    utilityFunction: UtilityFunction,
    possibleStates: AgentState[],
    marketConditions: MarketConditions
  ): { state: AgentState; utility: number } {
    let bestState = possibleStates[0];
    let bestUtility = -Infinity;
    
    for (const state of possibleStates) {
      const utility = this.calculateUtilityFromState(utilityFunction, state, marketConditions);
      
      if (utilityFunction.optimizationTarget === OptimizationTarget.MAXIMIZE && utility > bestUtility) {
        bestUtility = utility;
        bestState = state;
      } else if (utilityFunction.optimizationTarget === OptimizationTarget.MINIMIZE && utility < bestUtility) {
        bestUtility = utility;
        bestState = state;
      }
    }
    
    return { state: bestState, utility: bestUtility };
  }

  private calculateUtilityFromState(
    utilityFunction: UtilityFunction,
    state: AgentState,
    marketConditions: MarketConditions
  ): number {
    const parameterValues = this.extractParameterValues(state, marketConditions);
    
    switch (utilityFunction.type) {
      case UtilityType.PROFIT_MAXIMIZATION:
        return this.calculateProfitUtility(utilityFunction, parameterValues);
      case UtilityType.RISK_MINIMIZATION:
        return this.calculateRiskUtility(utilityFunction, parameterValues);
      default:
        return this.calculateWeightedUtility(utilityFunction, parameterValues);
    }
  }

  createUtilityFunction(
    name: string,
    type: UtilityType,
    parameters: UtilityParameter[],
    weights: number[],
    constraints: UtilityConstraint[],
    optimizationTarget: OptimizationTarget
  ): UtilityFunction {
    return {
      id: `util_${Date.now()}`,
      name,
      type,
      parameters,
      weights,
      constraints,
      optimizationTarget
    };
  }

  validateUtilityFunction(utilityFunction: UtilityFunction): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    // Check if parameters and weights have same length
    if (utilityFunction.parameters.length !== utilityFunction.weights.length) {
      errors.push('Parameters and weights arrays must have the same length');
    }
    
    // Check if weights sum to 1 for weighted utility
    if (utilityFunction.type === UtilityType.UTILITY_MAXIMIZATION) {
      const weightSum = utilityFunction.weights.reduce((sum, weight) => sum + weight, 0);
      if (Math.abs(weightSum - 1) > 0.01) {
        errors.push('Weights must sum to 1 for utility maximization');
      }
    }
    
    // Check parameter bounds
    for (const param of utilityFunction.parameters) {
      if (param.min !== undefined && param.max !== undefined && param.min >= param.max) {
        errors.push(`Parameter ${param.name} has invalid bounds`);
      }
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
}
