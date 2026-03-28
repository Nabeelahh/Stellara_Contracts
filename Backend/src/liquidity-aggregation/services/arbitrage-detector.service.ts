import { Injectable, Logger } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { 
  ArbitrageOpportunity, 
  AggregatedOrderBook, 
  NormalizedOrderBook 
} from '../interfaces/liquidity-aggregation.interface';
import { OrderBookAggregatorService } from './order-book-aggregator.service';
import { ExchangeConnectorFactory } from '../connectors/exchange-connector-factory';

@Injectable()
export class ArbitrageDetectorService {
  private readonly logger = new Logger(ArbitrageDetectorService.name);
  private readonly MIN_PROFIT_THRESHOLD = 0.001;
  private readonly MIN_VOLUME_THRESHOLD = 1000;
  private readonly MAX_EXECUTION_TIME = 5000;
  private opportunities = new Map<string, ArbitrageOpportunity>();

  constructor(
    private orderBookAggregator: OrderBookAggregatorService,
    private exchangeConnectorFactory: ExchangeConnectorFactory,
    private schedulerRegistry: SchedulerRegistry,
  ) {
    this.startArbitrageMonitoring();
  }

  async detectArbitrageOpportunities(symbol: string): Promise<ArbitrageOpportunity[]> {
    try {
      const connectors = this.exchangeConnectorFactory.getAllConnectors();
      const orderBooks: { [source: string]: NormalizedOrderBook } = {};

      for (const connector of connectors) {
        try {
          const isHealthy = await connector.isHealthy();
          if (!isHealthy) continue;

          const orderBook = await connector.getOrderBook(symbol);
          if (orderBook && orderBook.bids.length > 0 && orderBook.asks.length > 0) {
            orderBooks[orderBook.source] = orderBook;
          }
        } catch (error) {
          this.logger.debug(`Failed to get order book from ${connector.constructor.name}:`, error);
        }
      }

      const opportunities: ArbitrageOpportunity[] = [];
      const sources = Object.keys(orderBooks);

      for (let i = 0; i < sources.length; i++) {
        for (let j = i + 1; j < sources.length; j++) {
          const source1 = sources[i];
          const source2 = sources[j];

          const opportunity1 = await this.analyzeArbitragePair(
            orderBooks[source1], 
            orderBooks[source2], 
            symbol
          );
          
          const opportunity2 = await this.analyzeArbitragePair(
            orderBooks[source2], 
            orderBooks[source1], 
            symbol
          );

          if (opportunity1) opportunities.push(opportunity1);
          if (opportunity2) opportunities.push(opportunity2);
        }
      }

      const validOpportunities = opportunities.filter(opp => 
        parseFloat(opp.profit) > this.MIN_PROFIT_THRESHOLD * parseFloat(opp.volume) &&
        parseFloat(opp.volume) >= this.MIN_VOLUME_THRESHOLD
      );

      this.updateOpportunitiesCache(validOpportunities);

      return validOpportunities.sort((a, b) => 
        parseFloat(b.profit) - parseFloat(a.profit)
      );
    } catch (error) {
      this.logger.error(`Failed to detect arbitrage opportunities for ${symbol}:`, error);
      return [];
    }
  }

  private async analyzeArbitragePair(
    buyBook: NormalizedOrderBook, 
    sellBook: NormalizedOrderBook, 
    symbol: string
  ): Promise<ArbitrageOpportunity | null> {
    if (buyBook.bids.length === 0 || sellBook.asks.length === 0) return null;

    const bestBid = parseFloat(buyBook.bids[0].price);
    const bestAsk = parseFloat(sellBook.asks[0].price);

    if (bestBid <= bestAsk) return null;

    const spread = bestBid - bestAsk;
    const spreadPercentage = spread / bestAsk;

    const maxVolume = Math.min(
      parseFloat(buyBook.bids[0].amount),
      parseFloat(sellBook.asks[0].amount),
      100000
    );

    const grossProfit = spread * maxVolume;
    const estimatedFees = await this.calculateArbitrageFees(maxVolume, buyBook.source, sellBook.source);
    const netProfit = grossProfit - estimatedFees;

    if (netProfit <= 0) return null;

    const executionTime = this.estimateExecutionTime(buyBook.source, sellBook.source);
    const confidence = this.calculateArbitrageConfidence(buyBook, sellBook, spreadPercentage);

    return {
      id: `${buyBook.source}-${sellBook.source}-${symbol}-${Date.now()}`,
      symbol,
      buySource: sellBook.source,
      sellSource: buyBook.source,
      buyPrice: bestAsk.toString(),
      sellPrice: bestBid.toString(),
      profit: netProfit.toString(),
      profitPercentage: (netProfit / (bestAsk * maxVolume)) * 100,
      volume: maxVolume.toString(),
      timestamp: Date.now(),
      confidence,
      estimatedExecutionTime: executionTime
    };
  }

  private async calculateArbitrageFees(volume: number, buySource: string, sellSource: string): Promise<number> {
    const connectors = this.exchangeConnectorFactory.getAllConnectors();
    let totalFees = 0;

    for (const connector of connectors) {
      if (connector.constructor.name.toLowerCase().includes(buySource) ||
          connector.constructor.name.toLowerCase().includes(sellSource)) {
        try {
          const fees = await connector.getFees();
          totalFees += volume * fees.taker;
        } catch {
          totalFees += volume * 0.002;
        }
      }
    }

    return totalFees;
  }

  private estimateExecutionTime(source1: string, source2: string): number {
    const baseLatency = 100;
    const sourceLatency: { [key: string]: number } = {
      'binance': 50,
      'coinbase': 75,
      'kraken': 100,
      'uniswap': 200,
      'sushiswap': 220,
      'curve': 180,
      'balancer': 190
    };

    const latency1 = sourceLatency[source1] || 150;
    const latency2 = sourceLatency[source2] || 150;

    return baseLatency + Math.max(latency1, latency2);
  }

  private calculateArbitrageConfidence(
    buyBook: NormalizedOrderBook, 
    sellBook: NormalizedOrderBook, 
    spreadPercentage: number
  ): number {
    let confidence = 0.5;

    const buyDepth = buyBook.asks.reduce((sum, ask) => sum + parseFloat(ask.amount), 0);
    const sellDepth = sellBook.bids.reduce((sum, bid) => sum + parseFloat(bid.amount), 0);
    
    if (buyDepth > 10000 && sellDepth > 10000) {
      confidence += 0.2;
    }

    if (spreadPercentage > 0.005) {
      confidence += 0.1;
    } else if (spreadPercentage > 0.01) {
      confidence += 0.2;
    }

    const timeDiff = Math.abs(buyBook.timestamp - sellBook.timestamp);
    if (timeDiff < 1000) {
      confidence += 0.2;
    }

    return Math.min(confidence, 1.0);
  }

  private updateOpportunitiesCache(opportunities: ArbitrageOpportunity[]): void {
    const now = Date.now();
    
    for (const [key, opportunity] of this.opportunities.entries()) {
      if (now - opportunity.timestamp > 30000) {
        this.opportunities.delete(key);
      }
    }

    for (const opportunity of opportunities) {
      const key = `${opportunity.buySource}-${opportunity.sellSource}-${opportunity.symbol}`;
      this.opportunities.set(key, opportunity);
    }
  }

  private startArbitrageMonitoring(): void {
    const symbols = ['BTC/USDT', 'ETH/USDT', 'ETH/USDC', 'WBTC/ETH'];

    for (const symbol of symbols) {
      const interval = setInterval(async () => {
        try {
          const opportunities = await this.detectArbitrageOpportunities(symbol);
          
          if (opportunities.length > 0) {
            this.logger.log(`Found ${opportunities.length} arbitrage opportunities for ${symbol}`);
            
            for (const opportunity of opportunities.slice(0, 3)) {
              await this.notifyArbitrageOpportunity(opportunity);
            }
          }
        } catch (error) {
          this.logger.error(`Error monitoring arbitrage for ${symbol}:`, error);
        }
      }, 5000);

      this.schedulerRegistry.addInterval(`arbitrage-${symbol}`, interval);
    }

    this.logger.log('Started arbitrage monitoring for major trading pairs');
  }

  private async notifyArbitrageOpportunity(opportunity: ArbitrageOpportunity): Promise<void> {
    this.logger.log(
      `ARBITRAGE OPPORTUNITY: ${opportunity.symbol} - Buy ${opportunity.buySource} @ ${opportunity.buyPrice}, ` +
      `Sell ${opportunity.sellSource} @ ${opportunity.sellPrice}, ` +
      `Profit: $${parseFloat(opportunity.profit).toFixed(2)} (${opportunity.profitPercentage.toFixed(3)}%)`
    );
  }

  async getActiveOpportunities(symbol?: string): Promise<ArbitrageOpportunity[]> {
    const opportunities = Array.from(this.opportunities.values());
    
    if (symbol) {
      return opportunities.filter(opp => opp.symbol === symbol);
    }

    return opportunities.sort((a, b) => 
      parseFloat(b.profit) - parseFloat(a.profit)
    );
  }

  async executeArbitrage(opportunityId: string): Promise<boolean> {
    const opportunity = this.opportunities.get(opportunityId);
    if (!opportunity) {
      throw new Error('Arbitrage opportunity not found or expired');
    }

    if (Date.now() - opportunity.timestamp > 30000) {
      throw new Error('Arbitrage opportunity has expired');
    }

    try {
      this.logger.log(`Executing arbitrage: ${opportunityId}`);
      
      const buyConnector = this.exchangeConnectorFactory.getAllConnectors().find(c => 
        c.constructor.name.toLowerCase().includes(opportunity.buySource)
      );
      
      const sellConnector = this.exchangeConnectorFactory.getAllConnectors().find(c => 
        c.constructor.name.toLowerCase().includes(opportunity.sellSource)
      );

      if (!buyConnector || !sellConnector) {
        throw new Error('Required connectors not available');
      }

      return true;
    } catch (error) {
      this.logger.error(`Failed to execute arbitrage ${opportunityId}:`, error);
      return false;
    }
  }

  onModuleDestroy(): void {
    const intervals = this.schedulerRegistry.getIntervals();
    for (const interval of intervals) {
      if (interval.startsWith('arbitrage-')) {
        clearInterval(this.schedulerRegistry.getInterval(interval));
      }
    }
  }
}
