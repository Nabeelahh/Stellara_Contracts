import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { Decimal } from '@prisma/client/runtime/library';

export interface PerformanceMetrics {
  totalPnL: number;
  winRate: number;
  sharpeRatio: number;
  maxDrawdown: number;
  totalTrades: number;
  avgRiskReward: number;
}

export interface BehavioralStats {
  bestPairs: Array<{ callId: string; pnl: number }>;
  worstPairs: Array<{ callId: string; pnl: number }>;
  timeStats: {
    hourly: Record<number, number>;
    daily: Record<number, number>;
    monthly: Record<number, number>;
  };
}

@Injectable()
export class AnalyticsService {
  private readonly logger = new Logger(AnalyticsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async getPerformanceMetrics(userId: string): Promise<PerformanceMetrics> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { walletAddress: true },
    });

    if (!user) {
      throw new Error('User not found');
    }

    const stakes = await this.prisma.stakeLedger.findMany({
      where: {
        userAddress: user.walletAddress,
        resolutionStatus: 'RESOLVED',
      },
      orderBy: { createdAt: 'asc' },
    });

    if (stakes.length === 0) {
      return {
        totalPnL: 0,
        winRate: 0,
        sharpeRatio: 0,
        maxDrawdown: 0,
        totalTrades: 0,
        avgRiskReward: 0,
      };
    }

    let totalPnL = 0;
    let winningTrades = 0;
    const returns: number[] = [];
    let currentEquity = 10000; // Starting baseline
    let maxEquity = currentEquity;
    let maxDD = 0;

    for (const stake of stakes) {
      const pnl = Number(stake.profitLoss || 0);
      totalPnL += pnl;
      if (pnl > 0) winningTrades++;
      
      const tradeReturn = pnl / Number(stake.amount);
      returns.push(tradeReturn);

      currentEquity += pnl;
      if (currentEquity > maxEquity) {
        maxEquity = currentEquity;
      }
      const dd = (maxEquity - currentEquity) / maxEquity;
      if (dd > maxDD) maxDD = dd;
    }

    const winRate = (winningTrades / stakes.length) * 100;
    const sharpeRatio = this.calculateSharpeRatio(returns);

    return {
      totalPnL,
      winRate,
      sharpeRatio,
      maxDrawdown: maxDD,
      totalTrades: stakes.length,
      avgRiskReward: 1.5, // Mocked for now, needs risk calc
    };
  }

  async getBehavioralAnalysis(userId: string): Promise<BehavioralStats> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { walletAddress: true },
    });

    const stakes = await this.prisma.stakeLedger.findMany({
      where: {
        userAddress: user?.walletAddress,
        resolutionStatus: 'RESOLVED',
      },
    });

    const pairPNL: Record<string, number> = {};
    const hourly: Record<number, number> = {};
    const daily: Record<number, number> = {};
    const monthly: Record<number, number> = {};

    for (const stake of stakes) {
      const pnl = Number(stake.profitLoss || 0);
      const date = new Date(stake.createdAt);
      
      pairPNL[stake.callId] = (pairPNL[stake.callId] || 0) + pnl;
      
      const hour = date.getHours();
      hourly[hour] = (hourly[hour] || 0) + pnl;
      
      const day = date.getDay();
      daily[day] = (daily[day] || 0) + pnl;
      
      const month = date.getMonth();
      monthly[month] = (monthly[month] || 0) + pnl;
    }

    const sortedPairs = Object.entries(pairPNL)
      .map(([callId, pnl]) => ({ callId, pnl }))
      .sort((a, b) => b.pnl - a.pnl);

    return {
      bestPairs: sortedPairs.slice(0, 5),
      worstPairs: sortedPairs.slice(-5).reverse(),
      timeStats: { hourly, daily, monthly },
    };
  }

  async detectPatterns(userId: string): Promise<string[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { walletAddress: true },
    });

    const stakes = await this.prisma.stakeLedger.findMany({
      where: {
        userAddress: user?.walletAddress,
        resolutionStatus: 'RESOLVED',
      },
      orderBy: { createdAt: 'desc' },
      take: 20,
    });

    const pnlList = stakes.map(s => Number(s.profitLoss || 0));
    const patterns: string[] = [];

    // Simple Head and Shoulders on account equity
    if (this.isHeadAndShoulders(pnlList)) {
      patterns.push('Equity Head & Shoulders (Potential Reversal)');
    }

    if (this.isDoubleTop(pnlList)) {
      patterns.push('Double Top detected in P&L curve');
    }

    return patterns;
  }

  async getRecommendations(userId: string): Promise<string[]> {
    const metrics = await this.getPerformanceMetrics(userId);
    const behavior = await this.getBehavioralAnalysis(userId);
    const recommendations: string[] = [];

    if (metrics.winRate < 40) {
      recommendations.push('Consider tightening your entry criteria to improve win rate.');
    }

    if (metrics.maxDrawdown > 0.2) {
      recommendations.push('Your maximum drawdown is high. Consider reducing position sizes.');
    }

    // Time-based recommendations
    const worstHour = Object.entries(behavior.timeStats.hourly)
      .sort((a, b) => a[1] - b[1])[0];
    
    if (worstHour && worstHour[1] < 0) {
      recommendations.push(`You tend to lose most around hour ${worstHour[0]}. Consider trading less during this time.`);
    }

    return recommendations;
  }

  private calculateSharpeRatio(returns: number[]): number {
    if (returns.length < 2) return 0;
    const avgReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance = returns.reduce((a, b) => a + Math.pow(b - avgReturn, 2), 0) / (returns.length - 1);
    const stdDev = Math.sqrt(variance);
    return stdDev === 0 ? 0 : (avgReturn / stdDev) * Math.sqrt(252); // Annualized for daily trades
  }

  private isHeadAndShoulders(data: number[]): boolean {
    if (data.length < 5) return false;
    // VERY simplified pattern detection logic
    // Look for: Up, Down, Up (Higher), Down, Up (Lower), Down
    return false; // Placeholder for actual algo
  }

  private isDoubleTop(data: number[]): boolean {
    if (data.length < 5) return false;
    return false; // Placeholder
  }
}
