import { Injectable, Logger } from '@nestjs/common';
import { 
  GameTheoryScenario,
  GameType,
  PayoffMatrix,
  NashEquilibrium,
  Agent,
  AgentState,
  MarketConditions
} from '../interfaces/agent.interface';

@Injectable()
export class GameTheoryService {
  private readonly logger = new Logger(GameTheoryService.name);

  findNashEquilibrium(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    const equilibria: NashEquilibrium[] = [];
    
    switch (this.determineGameType(payoffMatrix)) {
      case GameType.PRISONERS_DILEMMA:
        equilibria.push(...this.solvePrisonersDilemma(payoffMatrix));
        break;
      
      case GameType.COURNOT_DUOPOLY:
        equilibria.push(...this.solveCournotDuopoly(payoffMatrix));
        break;
      
      case GameType.BERTRAND_DUOPOLY:
        equilibria.push(...this.solveBertrandDuopoly(payoffMatrix));
        break;
      
      case GameType.STACKELBERG:
        equilibria.push(...this.solveStackelberg(payoffMatrix));
        break;
      
      default:
        equilibria.push(...this.solveGeneralGame(payoffMatrix));
    }
    
    return equilibria;
  }

  private determineGameType(payoffMatrix: PayoffMatrix): GameType {
    const playerCount = payoffMatrix.players.length;
    
    if (playerCount === 2 && payoffMatrix.strategies[0].length === 2 && 
        payoffMatrix.strategies[1].length === 2) {
      // Check if it's Prisoner's Dilemma
      const [p1, p2] = payoffMatrix.players;
      const [s1, s2] = payoffMatrix.strategies[0];
      const payoffs = payoffMatrix.payoffs;
      
      // Prisoner's Dilemma: T > R > P > S and 2R > T + S
      const T = payoffs[0][0][0]; // Temptation
      const R = payoffs[0][0][1]; // Reward
      const P = payoffs[1][1][0]; // Punishment
      const S = payoffs[1][0][1]; // Sucker's payoff
      
      if (T > R && R > P && P > S && 2 * R > T + S) {
        return GameType.PRISONERS_DILEMMA;
      }
    }
    
    return GameType.CUSTOM;
  }

  private solvePrisonersDilemma(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    // In Prisoner's Dilemma, (Defect, Defect) is the Nash Equilibrium
    const equilibrium: NashEquilibrium = {
      strategies: {
        [payoffMatrix.players[0]]: 'Defect',
        [payoffMatrix.players[1]]: 'Defect'
      },
      payoffs: {
        [payoffMatrix.players[0]]: payoffMatrix.payoffs[1][1][0],
        [payoffMatrix.players[1]]: payoffMatrix.payoffs[1][1][1]
      },
      stability: 1.0
    };
    
    return [equilibrium];
  }

  private solveCournotDuopoly(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    // Cournot duopoly: each firm chooses quantity
    // Nash equilibrium where each firm's quantity is a best response to the other's
    const player1 = payoffMatrix.players[0];
    const player2 = payoffMatrix.players[1];
    
    // For simplicity, assume linear demand and constant marginal cost
    // q1* = (a - c) / 3, q2* = (a - c) / 3 for symmetric case
    
    const equilibriumQuantity = 100; // Placeholder calculation
    const equilibriumPrice = 50; // Placeholder calculation
    
    const equilibrium: NashEquilibrium = {
      strategies: {
        [player1]: `Produce ${equilibriumQuantity}`,
        [player2]: `Produce ${equilibriumQuantity}`
      },
      payoffs: {
        [player1]: equilibriumPrice * equilibriumQuantity,
        [player2]: equilibriumPrice * equilibriumQuantity
      },
      stability: 0.9
    };
    
    return [equilibrium];
  }

  private solveBertrandDuopoly(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    // Bertrand duopoly: each firm chooses price
    // Nash equilibrium is marginal cost pricing
    const player1 = payoffMatrix.players[0];
    const player2 = payoffMatrix.players[1];
    
    const marginalCost = 10; // Placeholder
    const marketDemand = 1000; // Placeholder
    
    const equilibriumPrice = marginalCost;
    const equilibriumQuantity = marketDemand / 2; // Split market equally
    
    const equilibrium: NashEquilibrium = {
      strategies: {
        [player1]: `Price ${equilibriumPrice}`,
        [player2]: `Price ${equilibriumPrice}`
      },
      payoffs: {
        [player1]: (equilibriumPrice - marginalCost) * equilibriumQuantity,
        [player2]: (equilibriumPrice - marginalCost) * equilibriumQuantity
      },
      stability: 1.0
    };
    
    return [equilibrium];
  }

  private solveStackelberg(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    // Stackelberg: leader-follower game
    const leader = payoffMatrix.players[0];
    const follower = payoffMatrix.players[1];
    
    // Leader moves first, follower best responds
    const leaderQuantity = 150; // Placeholder optimal leader quantity
    const followerQuantity = 75; // Placeholder best response
    const marketPrice = 25; // Placeholder resulting price
    
    const equilibrium: NashEquilibrium = {
      strategies: {
        [leader]: `Produce ${leaderQuantity}`,
        [follower]: `Produce ${followerQuantity}`
      },
      payoffs: {
        [leader]: marketPrice * leaderQuantity,
        [follower]: marketPrice * followerQuantity
      },
      stability: 0.95
    };
    
    return [equilibrium];
  }

  private solveGeneralGame(payoffMatrix: PayoffMatrix): NashEquilibrium[] {
    const equilibria: NashEquilibrium[] = [];
    const players = payoffMatrix.players;
    
    // Check each strategy combination for Nash equilibrium
    for (let i = 0; i < payoffMatrix.strategies[0].length; i++) {
      for (let j = 0; j < payoffMatrix.strategies[1].length; j++) {
        const strategyProfile = {
          [players[0]]: payoffMatrix.strategies[0][i],
          [players[1]]: payoffMatrix.strategies[1][j]
        };
        
        if (this.isNashEquilibrium(strategyProfile, payoffMatrix)) {
          const equilibrium: NashEquilibrium = {
            strategies: strategyProfile,
            payoffs: {
              [players[0]]: payoffMatrix.payoffs[i][j][0],
              [players[1]]: payoffMatrix.payoffs[i][j][1]
            },
            stability: this.calculateStability(strategyProfile, payoffMatrix)
          };
          
          equilibria.push(equilibrium);
        }
      }
    }
    
    return equilibria;
  }

  private isNashEquilibrium(
    strategyProfile: { [playerId: string]: string },
    payoffMatrix: PayoffMatrix
  ): boolean {
    const players = payoffMatrix.players;
    
    // Check if any player can improve their payoff by unilaterally deviating
    for (let playerIndex = 0; playerIndex < players.length; playerIndex++) {
      const playerId = players[playerIndex];
      const currentStrategy = strategyProfile[playerId];
      const currentPayoff = this.getPayoffForStrategy(strategyProfile, payoffMatrix, playerId);
      
      // Check all alternative strategies
      for (const alternativeStrategy of payoffMatrix.strategies[playerIndex]) {
        if (alternativeStrategy === currentStrategy) continue;
        
        const alternativeProfile = { ...strategyProfile };
        alternativeProfile[playerId] = alternativeStrategy;
        
        const alternativePayoff = this.getPayoffForStrategy(alternativeProfile, payoffMatrix, playerId);
        
        if (alternativePayoff > currentPayoff) {
          return false; // Player can improve by deviating
        }
      }
    }
    
    return true;
  }

  private getPayoffForStrategy(
    strategyProfile: { [playerId: string]: string },
    payoffMatrix: PayoffMatrix,
    playerId: string
  ): number {
    const playerIndex = payoffMatrix.players.indexOf(playerId);
    
    for (let i = 0; i < payoffMatrix.strategies[0].length; i++) {
      for (let j = 0; j < payoffMatrix.strategies[1].length; j++) {
        if (payoffMatrix.strategies[0][i] === strategyProfile[payoffMatrix.players[0]] &&
            payoffMatrix.strategies[1][j] === strategyProfile[payoffMatrix.players[1]]) {
          return payoffMatrix.payoffs[i][j][playerIndex];
        }
      }
    }
    
    return 0;
  }

  private calculateStability(
    strategyProfile: { [playerId: string]: string },
    payoffMatrix: PayoffMatrix
  ): number {
    // Calculate how stable the equilibrium is
    // Higher value means more stable (less incentive to deviate)
    let totalDeviationIncentive = 0;
    const players = payoffMatrix.players;
    
    for (let playerIndex = 0; playerIndex < players.length; playerIndex++) {
      const playerId = players[playerIndex];
      const currentPayoff = this.getPayoffForStrategy(strategyProfile, payoffMatrix, playerId);
      
      let maxAlternativePayoff = currentPayoff;
      
      for (const alternativeStrategy of payoffMatrix.strategies[playerIndex]) {
        if (alternativeStrategy === strategyProfile[playerId]) continue;
        
        const alternativeProfile = { ...strategyProfile };
        alternativeProfile[playerId] = alternativeStrategy;
        
        const alternativePayoff = this.getPayoffForStrategy(alternativeProfile, payoffMatrix, playerId);
        maxAlternativePayoff = Math.max(maxAlternativePayoff, alternativePayoff);
      }
      
      totalDeviationIncentive += (maxAlternativePayoff - currentPayoff);
    }
    
    // Return inverse of total deviation incentive (higher = more stable)
    return 1 / (1 + totalDeviationIncentive);
  }

  findDominantStrategies(payoffMatrix: PayoffMatrix): { [playerId: string]: string } {
    const dominantStrategies: { [playerId: string]: string } = {};
    const players = payoffMatrix.players;
    
    for (let playerIndex = 0; playerIndex < players.length; playerIndex++) {
      const playerId = players[playerIndex];
      dominantStrategies[playerId] = this.findDominantStrategy(payoffMatrix, playerIndex);
    }
    
    return dominantStrategies;
  }

  private findDominantStrategy(payoffMatrix: PayoffMatrix, playerIndex: number): string {
    const strategies = payoffMatrix.strategies[playerIndex];
    let dominantStrategy = strategies[0];
    
    for (let i = 0; i < strategies.length; i++) {
      let isDominant = true;
      
      for (let j = 0; j < strategies.length; j++) {
        if (i === j) continue;
        
        if (!this.dominates(payoffMatrix, playerIndex, i, j)) {
          isDominant = false;
          break;
        }
      }
      
      if (isDominant) {
        dominantStrategy = strategies[i];
        break;
      }
    }
    
    return dominantStrategy;
  }

  private dominates(
    payoffMatrix: PayoffMatrix,
    playerIndex: number,
    strategy1Index: number,
    strategy2Index: number
  ): boolean {
    // Strategy 1 dominates strategy 2 if it gives higher or equal payoff
    // against all possible strategies of other players
    
    for (let i = 0; i < payoffMatrix.strategies[1 - playerIndex].length; i++) {
      const payoff1 = this.getPayoffForStrategyIndices(payoffMatrix, strategy1Index, i, playerIndex);
      const payoff2 = this.getPayoffForStrategyIndices(payoffMatrix, strategy2Index, i, playerIndex);
      
      if (payoff1 < payoff2) {
        return false;
      }
    }
    
    return true;
  }

  private getPayoffForStrategyIndices(
    payoffMatrix: PayoffMatrix,
    player1StrategyIndex: number,
    player2StrategyIndex: number,
    playerIndex: number
  ): number {
    if (playerIndex === 0) {
      return payoffMatrix.payoffs[player1StrategyIndex][player2StrategyIndex][0];
    } else {
      return payoffMatrix.payoffs[player1StrategyIndex][player2StrategyIndex][1];
    }
  }

  calculateMixedStrategyEquilibrium(payoffMatrix: PayoffMatrix): { [playerId: string]: number[] } {
    // Calculate mixed strategy Nash equilibrium using linear programming
    const players = payoffMatrix.players;
    const mixedStrategies: { [playerId: string]: number[] } = {};
    
    for (let playerIndex = 0; playerIndex < players.length; playerIndex++) {
      const playerId = players[playerIndex];
      const strategyCount = payoffMatrix.strategies[playerIndex].length;
      
      // For 2x2 games, can calculate analytically
      if (strategyCount === 2 && players.length === 2) {
        mixedStrategies[playerId] = this.calculate2x2MixedStrategy(payoffMatrix, playerIndex);
      } else {
        // For larger games, use iterative method (simplified)
        mixedStrategies[playerId] = this.calculateIterativeMixedStrategy(payoffMatrix, playerIndex);
      }
    }
    
    return mixedStrategies;
  }

  private calculate2x2MixedStrategy(payoffMatrix: PayoffMatrix, playerIndex: number): number[] {
    // Calculate mixed strategy for 2x2 game
    // This is a simplified calculation
    const otherPlayerIndex = 1 - playerIndex;
    
    // Expected payoff for each strategy
    const expectedPayoffs = [0, 0];
    
    for (let i = 0; i < 2; i++) {
      for (let j = 0; j < 2; j++) {
        const payoff = playerIndex === 0 ? 
          payoffMatrix.payoffs[i][j][0] : 
          payoffMatrix.payoffs[j][i][1];
        expectedPayoffs[i] += payoff / 2;
      }
    }
    
    // Mixed strategy makes opponent indifferent
    const probability = 0.5; // Simplified - would solve indifference condition
    
    return [probability, 1 - probability];
  }

  private calculateIterativeMixedStrategy(payoffMatrix: PayoffMatrix, playerIndex: number): number[] {
    // Use iterative method to find mixed strategy equilibrium
    const strategyCount = payoffMatrix.strategies[playerIndex].length;
    let probabilities = new Array(strategyCount).fill(1 / strategyCount);
    
    // Simplified iterative update
    for (let iteration = 0; iteration < 100; iteration++) {
      const newProbabilities = [...probabilities];
      
      // Update based on regret matching
      const regrets = this.calculateRegrets(payoffMatrix, playerIndex, probabilities);
      
      for (let i = 0; i < strategyCount; i++) {
        if (regrets[i] > 0) {
          newProbabilities[i] += 0.01 * regrets[i];
        }
      }
      
      // Normalize
      const sum = newProbabilities.reduce((a, b) => a + b, 0);
      probabilities = newProbabilities.map(p => p / sum);
    }
    
    return probabilities;
  }

  private calculateRegrets(
    payoffMatrix: PayoffMatrix,
    playerIndex: number,
    probabilities: number[]
  ): number[] {
    const strategyCount = payoffMatrix.strategies[playerIndex].length;
    const regrets = new Array(strategyCount).fill(0);
    
    // Calculate expected payoff with current strategy
    let expectedPayoff = 0;
    for (let i = 0; i < strategyCount; i++) {
      // Simplified regret calculation
      expectedPayoff += probabilities[i] * Math.random() * 100; // Placeholder
    }
    
    // Calculate regret for each strategy
    for (let i = 0; i < strategyCount; i++) {
      const strategyPayoff = Math.random() * 100; // Placeholder
      regrets[i] = Math.max(0, strategyPayoff - expectedPayoff);
    }
    
    return regrets;
  }

  createGameTheoryScenario(
    name: string,
    type: GameType,
    players: string[],
    payoffMatrix: PayoffMatrix
  ): GameTheoryScenario {
    const nashEquilibria = this.findNashEquilibrium(payoffMatrix);
    const dominantStrategies = this.findDominantStrategies(payoffMatrix);
    
    return {
      id: `game_${Date.now()}`,
      name,
      type,
      players,
      payoffMatrix,
      nashEquilibria,
      dominantStrategies
    };
  }

  analyzeGameDynamics(
    scenario: GameTheoryScenario,
    iterations: number = 1000
  ): {
    convergence: boolean;
    finalStrategies: { [playerId: string]: string };
    averagePayoffs: { [playerId: string]: number };
  } {
    // Simulate repeated game to analyze dynamics
    const players = scenario.players;
    let currentStrategies: { [playerId: string]: string } = {};
    let totalPayoffs: { [playerId: string]: number[] } = {};
    
    // Initialize random strategies
    for (const player of players) {
      const playerIndex = players.indexOf(player);
      const strategies = scenario.payoffMatrix.strategies[playerIndex];
      currentStrategies[player] = strategies[Math.floor(Math.random() * strategies.length)];
      totalPayoffs[player] = [];
    }
    
    // Simulate iterations
    for (let i = 0; i < iterations; i++) {
      // Calculate payoffs for current strategies
      for (const player of players) {
        const payoff = this.getPayoffForStrategy(currentStrategies, scenario.payoffMatrix, player);
        totalPayoffs[player].push(payoff);
      }
      
      // Update strategies based on best response dynamics
      for (const player of players) {
        const playerIndex = players.indexOf(player);
        const bestStrategy = this.calculateBestResponse(scenario.payoffMatrix, playerIndex, currentStrategies);
        currentStrategies[player] = bestStrategy;
      }
    }
    
    // Calculate averages
    const averagePayoffs: { [playerId: string]: number } = {};
    for (const player of players) {
      const payoffs = totalPayoffs[player];
      averagePayoffs[player] = payoffs.reduce((sum, p) => sum + p, 0) / payoffs.length;
    }
    
    // Check convergence
    const convergence = this.checkConvergence(totalPayoffs);
    
    return {
      convergence,
      finalStrategies: currentStrategies,
      averagePayoffs
    };
  }

  private calculateBestResponse(
    payoffMatrix: PayoffMatrix,
    playerIndex: number,
    currentStrategies: { [playerId: string]: string }
  ): string {
    const strategies = payoffMatrix.strategies[playerIndex];
    let bestStrategy = strategies[0];
    let bestPayoff = -Infinity;
    
    for (const strategy of strategies) {
      const testStrategies = { ...currentStrategies };
      testStrategies[payoffMatrix.players[playerIndex]] = strategy;
      
      const payoff = this.getPayoffForStrategy(testStrategies, payoffMatrix, payoffMatrix.players[playerIndex]);
      
      if (payoff > bestPayoff) {
        bestPayoff = payoff;
        bestStrategy = strategy;
      }
    }
    
    return bestStrategy;
  }

  private checkConvergence(totalPayoffs: { [playerId: string]: number[] }): boolean {
    // Check if strategies have converged (payoffs stabilize)
    const convergenceThreshold = 0.01;
    
    for (const [playerId, payoffs] of Object.entries(totalPayoffs)) {
      if (payoffs.length < 10) continue;
      
      const recent = payoffs.slice(-10);
      const variance = this.calculateVariance(recent);
      
      if (variance > convergenceThreshold) {
        return false;
      }
    }
    
    return true;
  }

  private calculateVariance(values: number[]): number {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
    return squaredDiffs.reduce((sum, val) => sum + val, 0) / values.length;
  }
}
