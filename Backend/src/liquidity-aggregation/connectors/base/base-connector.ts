import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ExchangeConnector, NormalizedOrderBook, OrderRequest, TradeExecution } from '../interfaces/liquidity-aggregation.interface';

@Injectable()
export abstract class BaseExchangeConnector implements ExchangeConnector {
  protected readonly logger: Logger;
  protected readonly configService: ConfigService;

  constructor(configService: ConfigService, name: string) {
    this.configService = configService;
    this.logger = new Logger(name);
  }

  abstract connect(): Promise<void>;
  abstract disconnect(): Promise<void>;
  abstract getOrderBook(symbol: string): Promise<NormalizedOrderBook>;
  abstract executeOrder(order: OrderRequest): Promise<TradeExecution>;
  abstract getOrderStatus(orderId: string): Promise<TradeExecution>;
  abstract getSupportedPairs(): Promise<string[]>;
  abstract getFees(): Promise<{ maker: number; taker: number }>;
  abstract isHealthy(): Promise<boolean>;

  protected normalizeSymbol(symbol: string): string {
    return symbol.toUpperCase().replace('/', '');
  }

  protected denormalizeSymbol(symbol: string): string {
    return symbol.replace(/([A-Z])([A-Z])/g, '$1/$2');
  }

  protected calculateSpread(bids: any[], asks: any[]): string {
    if (bids.length === 0 || asks.length === 0) return '0';
    
    const bestBid = parseFloat(bids[0].price || bids[0][0]);
    const bestAsk = parseFloat(asks[0].price || asks[0][0]);
    
    return (bestAsk - bestBid).toString();
  }

  protected calculateDepth(levels: any[]): { [price: string]: string } {
    const depth: { [price: string]: string } = {};
    let cumulativeAmount = '0';

    for (const level of levels) {
      const price = level.price || level[0];
      const amount = level.amount || level[1];
      
      cumulativeAmount = (parseFloat(cumulativeAmount) + parseFloat(amount)).toString();
      depth[price] = cumulativeAmount;
    }

    return depth;
  }

  protected async withTimeout<T>(
    promise: Promise<T>, 
    timeoutMs: number = 5000
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Operation timeout')), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  protected async withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    delayMs: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxRetries) {
          throw lastError;
        }

        this.logger.warn(`Attempt ${attempt} failed, retrying in ${delayMs}ms:`, error);
        await new Promise(resolve => setTimeout(resolve, delayMs));
        delayMs *= 2;
      }
    }

    throw lastError!;
  }

  protected generateOrderId(): string {
    return `${this.constructor.name}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  protected parseAmount(amount: string | number): string {
    return typeof amount === 'string' ? amount : amount.toString();
  }

  protected parsePrice(price: string | number): string {
    return typeof price === 'string' ? price : price.toString();
  }
}
