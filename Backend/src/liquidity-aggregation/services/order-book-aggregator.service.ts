import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { 
  NormalizedOrderBook, 
  AggregatedOrderBook, 
  LiquiditySource,
  OrderBookLevel 
} from '../interfaces/liquidity-aggregation.interface';
import { ExchangeConnectorFactory } from '../connectors/exchange-connector-factory';

@Injectable()
export class OrderBookAggregatorService {
  private readonly logger = new Logger(OrderBookAggregatorService.name);
  private readonly orderBookCache = new Map<string, AggregatedOrderBook>();
  private readonly updateInterval = 1000;
  private updateTimers = new Map<string, NodeJS.Timeout>();

  constructor(
    private exchangeConnectorFactory: ExchangeConnectorFactory,
    private redis: Redis,
  ) {}

  async getAggregatedOrderBook(symbol: string): Promise<AggregatedOrderBook> {
    const cacheKey = `orderbook:${symbol}`;
    
    if (this.orderBookCache.has(cacheKey)) {
      return this.orderBookCache.get(cacheKey)!;
    }

    return await this.buildAggregatedOrderBook(symbol);
  }

  async buildAggregatedOrderBook(symbol: string): Promise<AggregatedOrderBook> {
    try {
      const connectors = this.exchangeConnectorFactory.getAllConnectors();
      const orderBooks: NormalizedOrderBook[] = [];

      for (const connector of connectors) {
        try {
          const isHealthy = await connector.isHealthy();
          if (!isHealthy) {
            this.logger.warn(`Connector ${connector.constructor.name} is unhealthy, skipping`);
            continue;
          }

          const orderBook = await this.withTimeout(
            connector.getOrderBook(symbol),
            3000
          );
          
          if (orderBook && orderBook.bids.length > 0 && orderBook.asks.length > 0) {
            orderBooks.push(orderBook);
          }
        } catch (error) {
          this.logger.error(`Failed to get order book from ${connector.constructor.name}:`, error);
        }
      }

      if (orderBooks.length === 0) {
        throw new Error(`No order books available for ${symbol}`);
      }

      const aggregatedBook = this.aggregateOrderBooks(orderBooks, symbol);
      
      await this.cacheOrderBook(symbol, aggregatedBook);
      this.startRealTimeUpdates(symbol);

      return aggregatedBook;
    } catch (error) {
      this.logger.error(`Failed to build aggregated order book for ${symbol}:`, error);
      throw error;
    }
  }

  private aggregateOrderBooks(orderBooks: NormalizedOrderBook[], symbol: string): AggregatedOrderBook {
    const allBids: OrderBookLevel[] = [];
    const allAsks: OrderBookLevel[] = [];
    const sources: string[] = [];
    const liquidityDistribution: { [source: string]: { bidVolume: string; askVolume: string; percentage: number } } = {};

    let totalBidVolume = 0;
    let totalAskVolume = 0;

    for (const orderBook of orderBooks) {
      sources.push(orderBook.source);
      
      allBids.push(...orderBook.bids);
      allAsks.push(...orderBook.asks);

      const bidVolume = orderBook.bids.reduce((sum, bid) => sum + parseFloat(bid.amount), 0);
      const askVolume = orderBook.asks.reduce((sum, ask) => sum + parseFloat(ask.amount), 0);
      
      totalBidVolume += bidVolume;
      totalAskVolume += askVolume;

      liquidityDistribution[orderBook.source] = {
        bidVolume: bidVolume.toString(),
        askVolume: askVolume.toString(),
        percentage: 0
      };
    }

    allBids.sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
    allAsks.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));

    const mergedBids = this.mergePriceLevels(allBids);
    const mergedAsks = this.mergePriceLevels(allAsks);

    for (const source in liquidityDistribution) {
      const sourceData = liquidityDistribution[source];
      const totalVolume = parseFloat(sourceData.bidVolume) + parseFloat(sourceData.askVolume);
      const grandTotalVolume = totalBidVolume + totalAskVolume;
      sourceData.percentage = grandTotalVolume > 0 ? (totalVolume / grandTotalVolume) * 100 : 0;
    }

    const spread = this.calculateWeightedSpread(mergedBids, mergedAsks);
    const weightedSpread = this.calculateWeightedSpread(mergedBids, mergedAsks);

    return {
      symbol,
      bids: mergedBids.slice(0, 50),
      asks: mergedAsks.slice(0, 50),
      timestamp: Date.now(),
      sources,
      totalVolume: {
        bid: totalBidVolume.toString(),
        ask: totalAskVolume.toString()
      },
      weightedSpread,
      liquidityDistribution
    };
  }

  private mergePriceLevels(levels: OrderBookLevel[]): OrderBookLevel[] {
    const priceMap = new Map<string, OrderBookLevel>();

    for (const level of levels) {
      const existing = priceMap.get(level.price);
      if (existing) {
        const newAmount = parseFloat(existing.amount) + parseFloat(level.amount);
        priceMap.set(level.price, {
          ...existing,
          amount: newAmount.toString(),
          timestamp: Math.max(existing.timestamp, level.timestamp)
        });
      } else {
        priceMap.set(level.price, level);
      }
    }

    return Array.from(priceMap.values());
  }

  private calculateWeightedSpread(bids: OrderBookLevel[], asks: OrderBookLevel[]): string {
    if (bids.length === 0 || asks.length === 0) return '0';

    const bestBid = parseFloat(bids[0].price);
    const bestAsk = parseFloat(asks[0].price);
    
    return (bestAsk - bestBid).toString();
  }

  private async cacheOrderBook(symbol: string, orderBook: AggregatedOrderBook): Promise<void> {
    const cacheKey = `orderbook:${symbol}`;
    this.orderBookCache.set(cacheKey, orderBook);

    try {
      await this.redis.setex(
        cacheKey,
        30,
        JSON.stringify(orderBook)
      );
    } catch (error) {
      this.logger.error('Failed to cache order book:', error);
    }
  }

  private startRealTimeUpdates(symbol: string): void {
    const cacheKey = `orderbook:${symbol}`;
    
    if (this.updateTimers.has(cacheKey)) {
      clearInterval(this.updateTimers.get(cacheKey)!);
    }

    const timer = setInterval(async () => {
      try {
        await this.buildAggregatedOrderBook(symbol);
      } catch (error) {
        this.logger.error(`Failed to update order book for ${symbol}:`, error);
      }
    }, this.updateInterval);

    this.updateTimers.set(cacheKey, timer);
  }

  stopRealTimeUpdates(symbol: string): void {
    const cacheKey = `orderbook:${symbol}`;
    const timer = this.updateTimers.get(cacheKey);
    
    if (timer) {
      clearInterval(timer);
      this.updateTimers.delete(cacheKey);
    }
  }

  async getLiquiditySources(): Promise<LiquiditySource[]> {
    const connectors = this.exchangeConnectorFactory.getAllConnectors();
    const sources: LiquiditySource[] = [];

    for (const connector of connectors) {
      try {
        const isHealthy = await connector.isHealthy();
        const fees = await connector.getFees();
        const supportedPairs = await connector.getSupportedPairs();

        sources.push({
          id: connector.constructor.name.toLowerCase().replace('connector', ''),
          name: connector.constructor.name.replace('Connector', ''),
          type: connector.constructor.name.toLowerCase().includes('uniswap') || 
                connector.constructor.name.toLowerCase().includes('sushi') ||
                connector.constructor.name.toLowerCase().includes('curve') ||
                connector.constructor.name.toLowerCase().includes('balancer') ? 'dex' : 'cex',
          isActive: isHealthy,
          priority: this.getPriority(connector.constructor.name),
          fees,
          latency: Math.random() * 100 + 50,
          reliability: isHealthy ? 0.99 : 0.5,
          supportedPairs
        });
      } catch (error) {
        this.logger.error(`Failed to get info for ${connector.constructor.name}:`, error);
      }
    }

    return sources.sort((a, b) => b.priority - a.priority);
  }

  private getPriority(connectorName: string): number {
    const priorities: { [key: string]: number } = {
      'BinanceConnector': 100,
      'CoinbaseConnector': 95,
      'KrakenConnector': 90,
      'UniswapConnector': 85,
      'SushiswapConnector': 80,
      'CurveConnector': 75,
      'BalancerConnector': 70
    };
    return priorities[connectorName] || 50;
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Operation timeout')), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  async clearCache(symbol?: string): Promise<void> {
    if (symbol) {
      const cacheKey = `orderbook:${symbol}`;
      this.orderBookCache.delete(cacheKey);
      this.stopRealTimeUpdates(symbol);
      
      try {
        await this.redis.del(cacheKey);
      } catch (error) {
        this.logger.error('Failed to clear cache:', error);
      }
    } else {
      this.orderBookCache.clear();
      
      for (const [symbol] of this.updateTimers) {
        this.stopRealTimeUpdates(symbol.replace('orderbook:', ''));
      }
      
      try {
        const keys = await this.redis.keys('orderbook:*');
        if (keys.length > 0) {
          await this.redis.del(...keys);
        }
      } catch (error) {
        this.logger.error('Failed to clear all cache:', error);
      }
    }
  }
}
