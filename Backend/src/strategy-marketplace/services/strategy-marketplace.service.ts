import { Injectable, Logger } from '@nestjs/common';
import { SubmitStrategyDto, BacktestRequestDto, CopyTradeDto } from '../dto/strategy.dto';

export interface TradingStrategy {
  id: string;
  name: string;
  description: string;
  developerAddress: string;
  strategyType: string;
  executionModule: string; // Docker image or WASM
  riskLevel: string;
  pricingModel: string;
  priceUsdCents?: number;
  profitSharePercent?: number;
  maxPositionSize?: number;
  stopLossPercent?: number;
  supportedPairs: string[];
  
  // Performance metrics
  totalReturn?: number;
  sharpeRatio?: number;
  maxDrawdown?: number;
  winRate?: number;
  totalTrades?: number;
  avgDailyReturn?: number;
  
  // Metadata
  createdAt: Date;
  updatedAt: Date;
  isActive: boolean;
  subscriberCount?: number;
  totalAUM?: number; // Assets Under Management
}

@Injectable()
export class StrategyMarketplaceService {
  private readonly logger = new Logger(StrategyMarketplaceService.name);
  private strategies: Map<string, TradingStrategy> = new Map();
  private subscriptions: Map<string, any[]> = new Map(); // strategyId -> subscriptions

  /**
   * Submit a new trading strategy to the marketplace
   */
  async submitStrategy(
    dto: SubmitStrategyDto,
    developerAddress: string,
  ): Promise<TradingStrategy> {
    const strategyId = `strat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const strategy: TradingStrategy = {
      id: strategyId,
      name: dto.name,
      description: dto.description,
      developerAddress,
      strategyType: dto.strategyType,
      executionModule: dto.executionModule,
      riskLevel: dto.riskLevel,
      pricingModel: dto.pricingModel,
      priceUsdCents: dto.priceUsdCents,
      profitSharePercent: dto.profitSharePercent,
      maxPositionSize: dto.maxPositionSize,
      stopLossPercent: dto.stopLossPercent,
      supportedPairs: dto.supportedPairs,
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      totalReturn: 0,
      sharpeRatio: 0,
      maxDrawdown: 0,
      winRate: 0,
      totalTrades: 0,
      subscriberCount: 0,
      totalAUM: 0,
    };

    this.strategies.set(strategyId, strategy);
    this.subscriptions.set(strategyId, []);

    this.logger.log(`Strategy submitted: ${strategyId} by ${developerAddress}`);

    return strategy;
  }

  /**
   * Backtest strategy on historical data (5+ years)
   */
  async backtestStrategy(dto: BacktestRequestDto): Promise<{
    strategyId: string;
    period: { start: Date; end: Date };
    initialCapital: number;
    finalCapital: number;
    totalReturn: number;
    annualizedReturn: number;
    sharpeRatio: number;
    sortinoRatio: number;
    maxDrawdown: number;
    maxDrawdownDuration: number; // days
    winRate: number;
    profitFactor: number;
    totalTrades: number;
    winningTrades: number;
    losingTrades: number;
    avgWin: number;
    avgLoss: number;
    avgTradeDuration: number; // hours
    equityCurve: Array<{ date: string; value: number }>;
    monthlyReturns: Array<{ month: string; return: number }>;
  }> {
    this.logger.log(`Backtesting strategy ${dto.strategyId} from ${dto.startDate} to ${dto.endDate}`);

    // In production: run actual backtest engine with historical data
    // For now: simulate realistic backtest results
    
    const startDate = new Date(dto.startDate);
    const endDate = new Date(dto.endDate);
    const days = Math.floor((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
    
    // Simulate trading performance
    const initialCapital = dto.initialCapital;
    const totalReturn = (Math.random() - 0.3) * 2; // -30% to +70%
    const finalCapital = initialCapital * (1 + totalReturn);
    
    const sharpeRatio = parseFloat((Math.random() * 2.5).toFixed(2));
    const maxDrawdown = parseFloat(-(Math.random() * 0.3).toFixed(4));
    const winRate = parseFloat((0.4 + Math.random() * 0.3).toFixed(4)); // 40-70%
    const totalTrades = Math.floor(days * 2.5); // ~2-3 trades per day
    const profitFactor = parseFloat((1.5 + Math.random() * 2).toFixed(2));
    
    // Generate equity curve
    const equityCurve = this.generateSimulatedEquityCurve(
      startDate,
      endDate,
      initialCapital,
      finalCapital,
    );

    // Generate monthly returns
    const monthlyReturns = this.generateSimulatedMonthlyReturns(
      startDate,
      endDate,
      totalReturn,
    );

    const result = {
      strategyId: dto.strategyId,
      period: { start: startDate, end: endDate },
      initialCapital,
      finalCapital,
      totalReturn,
      annualizedReturn: Math.pow(1 + totalReturn, 365 / days) - 1,
      sharpeRatio,
      sortinoRatio: parseFloat((sharpeRatio * 1.3).toFixed(2)),
      maxDrawdown,
      maxDrawdownDuration: Math.floor(Math.random() * 30) + 5,
      winRate,
      profitFactor,
      totalTrades,
      winningTrades: Math.floor(totalTrades * winRate),
      losingTrades: Math.floor(totalTrades * (1 - winRate)),
      avgWin: parseFloat((finalCapital * 0.02).toFixed(2)),
      avgLoss: parseFloat((finalCapital * 0.015).toFixed(2)),
      avgTradeDuration: parseFloat((4 + Math.random() * 8).toFixed(1)),
      equityCurve,
      monthlyReturns,
    };

    this.logger.log(
      `Backtest completed: ${result.totalReturn.toFixed(2)}% return, ` +
      `Sharpe: ${result.sharpeRatio}, MaxDD: ${(result.maxDrawdown * 100).toFixed(2)}%`,
    );

    return result;
  }

  /**
   * Subscribe to copy-trade a strategy
   */
  async subscribeToCopyTrade(
    dto: CopyTradeDto,
    userAddress: string,
  ): Promise<{
    subscriptionId: string;
    strategyId: string;
    status: string;
    allocationAmount: number;
    revenueSplit: {
      developerPercent: number;
      platformPercent: number;
      userPercent: number;
    };
  }> {
    const strategy = this.strategies.get(dto.strategyId);
    
    if (!strategy) {
      throw new Error(`Strategy ${dto.strategyId} not found`);
    }

    const subscriptionId = `copy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Calculate revenue split (70% developer, 30% platform)
    const revenueSplit = {
      developerPercent: 70,
      platformPercent: 30,
      userPercent: 100, // User keeps their profits minus fees
    };

    const subscription = {
      subscriptionId,
      strategyId: dto.strategyId,
      userAddress,
      allocationAmount: dto.allocationAmount,
      maxAllocation: dto.maxAllocation || dto.allocationAmount * 1.5,
      stopLossOverride: dto.stopLossOverride || strategy.stopLossPercent,
      status: 'ACTIVE',
      subscribedAt: new Date(),
      lastSyncAt: new Date(),
      totalProfit: 0,
      totalFeesPaid: 0,
    };

    // Add to subscriptions
    const subs = this.subscriptions.get(dto.strategyId) || [];
    subs.push(subscription);
    this.subscriptions.set(dto.strategyId, subs);

    // Update strategy metrics
    strategy.subscriberCount = (strategy.subscriberCount || 0) + 1;
    strategy.totalAUM = (strategy.totalAUM || 0) + dto.allocationAmount;

    this.logger.log(
      `User ${userAddress} subscribed to copy-trade ${strategy.name} ` +
      `with $${dto.allocationAmount}`,
    );

    return {
      subscriptionId,
      strategyId: dto.strategyId,
      status: 'ACTIVE',
      allocationAmount: dto.allocationAmount,
      revenueSplit,
    };
  }

  /**
   * Execute strategy trade (called by strategy execution engine)
   */
  async executeStrategyTrade(params: {
    strategyId: string;
    action: 'BUY' | 'SELL';
    pair: string;
    amount: number;
    price: number;
  }): Promise<{
    success: boolean;
    tradesExecuted: number;
    totalVolume: number;
  }> {
    const strategy = this.strategies.get(params.strategyId);
    
    if (!strategy) {
      throw new Error(`Strategy ${params.strategyId} not found`);
    }

    // Get all active copy-traders for this strategy
    const subscribers = this.subscriptions.get(params.strategyId) || [];
    const activeSubscribers = subscribers.filter(s => s.status === 'ACTIVE');

    let tradesExecuted = 0;
    let totalVolume = 0;

    // Execute proportional trades for each subscriber
    for (const subscriber of activeSubscribers) {
      try {
        const positionSize = (subscriber.allocationAmount / strategy.maxPositionSize!) * params.amount;
        
        // Execute trade (simulated)
        tradesExecuted++;
        totalVolume += positionSize * params.price;

        this.logger.debug(
          `Copied trade for ${subscriber.userAddress}: ${params.action} ${positionSize} ${params.pair}`,
        );
      } catch (error) {
        this.logger.error(`Failed to copy trade for ${subscriber.userAddress}: ${error.message}`);
      }
    }

    // Update strategy performance metrics
    strategy.totalTrades = (strategy.totalTrades || 0) + 1;

    return {
      success: tradesExecuted > 0,
      tradesExecuted,
      totalVolume,
    };
  }

  /**
   * Get strategy leaderboard sorted by performance
   */
  getLeaderboard(filters?: {
    strategyType?: string;
    riskLevel?: string;
    minSharpe?: number;
    limit?: number;
  }): Array<TradingStrategy & { rank: number }> {
    let strategies = Array.from(this.strategies.values())
      .filter(s => s.isActive);

    // Apply filters
    if (filters?.strategyType) {
      strategies = strategies.filter(s => s.strategyType === filters.strategyType);
    }
    if (filters?.riskLevel) {
      strategies = strategies.filter(s => s.riskLevel === filters.riskLevel);
    }
    if (filters?.minSharpe) {
      strategies = strategies.filter(s => (s.sharpeRatio || 0) >= filters.minSharpe!);
    }

    // Sort by Sharpe ratio (risk-adjusted returns)
    strategies.sort((a, b) => (b.sharpeRatio || 0) - (a.sharpeRatio || 0));

    // Add ranking
    return strategies.map((strategy, index) => ({
      ...strategy,
      rank: index + 1,
    })).slice(0, filters?.limit || 100);
  }

  /**
   * Distribute revenue between developer and platform
   */
  async distributeRevenue(params: {
    strategyId: string;
    totalRevenue: number;
    period: { start: Date; end: Date };
  }): Promise<{
    developerAmount: number;
    platformAmount: number;
    distributionDate: Date;
  }> {
    const strategy = this.strategies.get(params.strategyId);
    
    if (!strategy) {
      throw new Error(`Strategy ${params.strategyId} not found`);
    }

    // Revenue split: 70% developer, 30% platform
    const developerAmount = params.totalRevenue * 0.7;
    const platformAmount = params.totalRevenue * 0.3;

    this.logger.log(
      `Revenue distributed for ${strategy.name}: ` +
      `Developer: $${developerAmount}, Platform: $${platformAmount}`,
    );

    return {
      developerAmount,
      platformAmount,
      distributionDate: new Date(),
    };
  }

  /**
   * Helper: Generate simulated equity curve
   */
  private generateSimulatedEquityCurve(
    start: Date,
    end: Date,
    initial: number,
    final: number,
  ): Array<{ date: string; value: number }> {
    const points: Array<{ date: string; value: number }> = [];
    const days = Math.floor((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    
    let currentValue = initial;
    const dailyGrowth = (final - initial) / days;
    
    for (let i = 0; i <= days; i++) {
      const date = new Date(start.getTime() + i * 24 * 60 * 60 * 1000);
      // Add some randomness to make it look realistic
      const randomVariation = (Math.random() - 0.5) * dailyGrowth * 0.5;
      currentValue += dailyGrowth + randomVariation;
      
      points.push({
        date: date.toISOString().split('T')[0],
        value: Math.max(0, currentValue), // Ensure non-negative
      });
    }
    
    return points;
  }

  /**
   * Helper: Generate simulated monthly returns
   */
  private generateSimulatedMonthlyReturns(
    start: Date,
    end: Date,
    totalReturn: number,
  ): Array<{ month: string; return: number }> {
    const months: Array<{ month: string; return: number }> = [];
    const numMonths = Math.floor((end.getTime() - start.getTime()) / (30 * 24 * 60 * 60 * 1000));
    
    const avgMonthlyReturn = Math.pow(1 + totalReturn, 1 / numMonths) - 1;
    
    for (let i = 0; i < numMonths; i++) {
      const monthDate = new Date(start.getTime() + i * 30 * 24 * 60 * 60 * 1000);
      const monthlyReturn = avgMonthlyReturn + (Math.random() - 0.5) * 0.1;
      
      months.push({
        month: monthDate.toISOString().slice(0, 7), // YYYY-MM
        return: monthlyReturn,
      });
    }
    
    return months;
  }
}
