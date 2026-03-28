import { Injectable, Logger } from '@nestjs/common';
import { CommitRevealService } from './commit-reveal.service';
import { ThresholdEncryptionService } from './threshold-encryption.service';
import { OrderSide, OrderType } from '../dto/order.dto';

export interface DEXRoute {
  dexId: string;
  dexName: string;
  pair: string;
  price: number;
  liquidity: number;
  fee: number; // in basis points
  estimatedSlippage: number; // in basis points
  executionTime: number; // ms
}

export interface ExecutionPlan {
  routes: DEXRoute[];
  totalExpectedOutput: number;
  totalFees: number;
  averageSlippage: number;
  sandwichRiskScore: number; // 0-100
  recommendedRoute: string;
}

@Injectable()
export class IntelligentOrderRouter {
  private readonly logger = new Logger(IntelligentOrderRouter.name);
  
  // Simulated DEX liquidity pools (in production: fetch from real DEXes)
  private readonly dexPools = new Map<string, DEXRoute[]>([
    [
      'XLM/USDC',
      [
        {
          dexId: 'stellar_lobe',
          dexName: 'Stellar Lobe',
          pair: 'XLM/USDC',
          price: 0.1250,
          liquidity: 1000000,
          fee: 30, // 0.3%
          estimatedSlippage: 10,
          executionTime: 3000,
        },
        {
          dexId: 'aquarius',
          dexName: 'Aquarius',
          pair: 'XLM/USDC',
          price: 0.1248,
          liquidity: 500000,
          fee: 30,
          estimatedSlippage: 15,
          executionTime: 4000,
        },
        {
          dexId: 'lumenswap',
          dexName: 'LumenSwap',
          pair: 'XLM/USDC',
          price: 0.1252,
          liquidity: 750000,
          fee: 25,
          estimatedSlippage: 12,
          executionTime: 3500,
        },
      ],
    ],
  ]);

  constructor(
    private readonly commitRevealService: CommitRevealService,
    private readonly thresholdEncryption: ThresholdEncryptionService,
  ) {}

  /**
   * Find optimal routing across multiple DEXes for best execution
   */
  async findOptimalRoute(params: {
    side: OrderSide;
    pair: string;
    amount: number;
    maxSlippageBps: number;
  }): Promise<ExecutionPlan> {
    const routes = this.dexPools.get(params.pair) || [];
    
    if (routes.length === 0) {
      throw new Error(`No liquidity found for pair: ${params.pair}`);
    }

    // Analyze each route
    const analyzedRoutes = routes.map(route => {
      const expectedOutput = this.calculateExpectedOutput({
        side: params.side,
        amount: params.amount,
        price: route.price,
        fee: route.fee,
        slippage: route.estimatedSlippage,
      });

      return {
        ...route,
        expectedOutput,
        effectivePrice: expectedOutput / params.amount,
      };
    });

    // Sort by best execution (highest output for sell, lowest cost for buy)
    analyzedRoutes.sort((a, b) => {
      if (params.side === OrderSide.SELL) {
        return b.expectedOutput - a.expectedOutput;
      } else {
        return a.expectedOutput - b.expectedOutput;
      }
    });

    // Check for sandwich attack risk
    const sandwichRiskScore = this.assessSandwichRisk({
      amount: params.amount,
      liquidity: analyzedRoutes[0].liquidity,
      slippage: params.maxSlippageBps,
      marketVolatility: 0.02, // 2% volatility assumption
    });

    // Split large orders across multiple DEXes to minimize slippage
    const splitRoutes = this.splitOrderForBestExecution({
      amount: params.amount,
      routes: analyzedRoutes,
      maxSlippage: params.maxSlippageBps,
    });

    const totalExpectedOutput = splitRoutes.reduce(
      (sum, route) => sum + this.calculateExpectedOutput({
        side: params.side,
        amount: route.amount,
        price: route.price,
        fee: route.fee,
        slippage: route.estimatedSlippage,
      }),
      0,
    );

    const totalFees = splitRoutes.reduce(
      (sum, route) => sum + (route.amount * route.price * route.fee / 10000),
      0,
    );

    const averageSlippage = splitRoutes.reduce(
      (sum, route) => sum + route.estimatedSlippage,
      0,
    ) / splitRoutes.length;

    return {
      routes: splitRoutes,
      totalExpectedOutput,
      totalFees,
      averageSlippage,
      sandwichRiskScore,
      recommendedRoute: splitRoutes[0].dexId,
    };
  }

  /**
   * Execute order with MEV protection
   */
  async executeWithMEVProtection(params: {
    commitmentId: string;
    executionPlan: ExecutionPlan;
    useThresholdEncryption: boolean;
  }): Promise<{
    success: boolean;
    executedAmount: number;
    actualSlippage: number;
    mevRefund?: number;
    txHashes: string[];
  }> {
    const commitment = this.commitRevealService.getCommitment(params.commitmentId);
    
    if (!commitment) {
      throw new Error('Commitment not found');
    }

    this.logger.log(`Executing order ${params.commitmentId} with MEV protection`);

    const txHashes: string[] = [];
    let totalExecuted = 0;
    let totalSlippage = 0;

    // Execute on each route in the plan
    for (const route of params.executionPlan.routes) {
      try {
        // Simulate DEX swap transaction
        const txHash = await this.executeDexSwap({
          side: commitment.side as OrderSide,
          pair: route.pair,
          amount: this.getAmountForRoute(commitment.amount, route),
          dexId: route.dexId,
          minAmountOut: this.calculateMinAmountOut(commitment, route),
        });

        txHashes.push(txHash);
        totalExecuted += commitment.amount;
        totalSlippage += route.estimatedSlippage;
        
        this.logger.log(`Executed on ${route.dexName}: ${txHash}`);
      } catch (error) {
        this.logger.error(`Failed to execute on ${route.dexName}: ${error.message}`);
        // Continue with other routes (partial execution)
      }
    }

    // Calculate actual slippage
    const actualSlippage = totalSlippage / params.executionPlan.routes.length;

    // Check if slippage was within tolerance
    const slippageWithinTolerance = actualSlippage <= commitment.maxSlippageBps;

    // Calculate MEV refund if user experienced slippage < their max
    let mevRefund: number | undefined;
    if (slippageWithinTolerance && actualSlippage < commitment.maxSlippageBps) {
      mevRefund = (commitment.maxSlippageBps - actualSlippage) / 10000 * commitment.amount;
      this.logger.log(`MEV refund calculated: ${mevRefund}`);
    }

    // Mark commitment as executed
    this.commitRevealService.markAsExecuted(params.commitmentId);

    return {
      success: totalExecuted > 0,
      executedAmount: totalExecuted,
      actualSlippage,
      mevRefund,
      txHashes,
    };
  }

  /**
   * Detect potential sandwich attacks
   */
  detectSandwichAttack(params: {
    pendingOrders: Array<{ amount: number; side: OrderSide }>;
    timeWindowMs: number;
  }): {
    isDetected: boolean;
    confidence: number;
    pattern: string;
    recommendedAction: 'PROCEED' | 'DELAY' | 'SPLIT' | 'CANCEL';
  } {
    // Analyze order flow patterns for sandwich indicators
    const largeBuyOrders = params.pendingOrders.filter(
      o => o.side === OrderSide.BUY && o.amount > 10000,
    );

    const largeSellOrders = params.pendingOrders.filter(
      o => o.side === OrderSide.SELL && o.amount > 10000,
    );

    // Sandwich pattern: large buy followed by target order, then large sell
    const hasSuspiciousPattern = 
      largeBuyOrders.length > 0 && 
      largeSellOrders.length > 0 &&
      Math.abs(largeBuyOrders.length - largeSellOrders.length) <= 1;

    let confidence = 0;
    let recommendedAction: 'PROCEED' | 'DELAY' | 'SPLIT' | 'CANCEL' = 'PROCEED';

    if (hasSuspiciousPattern) {
      confidence = 0.7;
      recommendedAction = 'SPLIT';
      
      // Increase confidence if orders are very close in time
      if (params.timeWindowMs < 1000) {
        confidence = 0.9;
        recommendedAction = 'DELAY';
      }
    }

    return {
      isDetected: confidence > 0.5,
      confidence,
      pattern: hasSuspiciousPattern ? 'BUY_TARGET_SELL' : 'NORMAL',
      recommendedAction,
    };
  }

  /**
   * Helper: Calculate expected output from a trade
   */
  private calculateExpectedOutput(params: {
    side: OrderSide;
    amount: number;
    price: number;
    fee: number;
    slippage: number;
  }): number {
    const grossValue = params.amount * params.price;
    const feeAmount = grossValue * (params.fee / 10000);
    const slippageAmount = grossValue * (params.slippage / 10000);
    
    return grossValue - feeAmount - slippageAmount;
  }

  /**
   * Helper: Assess sandwich attack risk score
   */
  private assessSandwichRisk(params: {
    amount: number;
    liquidity: number;
    slippage: number;
    marketVolatility: number;
  }): number {
    let riskScore = 0;

    // Large order relative to liquidity increases risk
    const sizeRatio = params.amount / params.liquidity;
    riskScore += Math.min(sizeRatio * 100, 40);

    // High slippage tolerance attracts MEV bots
    riskScore += Math.min(params.slippage / 10, 30);

    // Market volatility increases uncertainty
    riskScore += params.marketVolatility * 100;

    return Math.min(riskScore, 100);
  }

  /**
   * Helper: Split large order across multiple DEXes
   */
  private splitOrderForBestExecution(params: {
    amount: number;
    routes: any[];
    maxSlippage: number;
  }): any[] {
    // Simple pro-rata split based on liquidity
    const totalLiquidity = params.routes.reduce((sum, r) => sum + r.liquidity, 0);
    
    return params.routes.map(route => ({
      ...route,
      amount: (route.liquidity / totalLiquidity) * params.amount,
    })).filter(r => r.amount > 0);
  }

  /**
   * Helper: Get amount for specific route
   */
  private getAmountForRoute(totalAmount: number, route: any): number {
    return route.amount || totalAmount / 3; // Default equal split
  }

  /**
   * Helper: Calculate minimum amount out (for slippage protection)
   */
  private calculateMinAmountOut(commitment: any, route: any): number {
    const expectedOutput = this.calculateExpectedOutput({
      side: commitment.side as OrderSide,
      amount: commitment.amount,
      price: route.price,
      fee: route.fee,
      slippage: route.estimatedSlippage,
    });
    
    // Apply max slippage tolerance
    return expectedOutput * (1 - commitment.maxSlippageBps / 10000);
  }

  /**
   * Helper: Simulate DEX swap
   */
  private async executeDexSwap(params: {
    side: OrderSide;
    pair: string;
    amount: number;
    dexId: string;
    minAmountOut: number;
  }): Promise<string> {
    // In production: actual DEX integration via Stellar SDK
    // For now: simulate with mock transaction hash
    return `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
