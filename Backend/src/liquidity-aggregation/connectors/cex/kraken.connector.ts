import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class KrakenConnector extends BaseExchangeConnector {
  private apiKey: string;
  private apiSecret: string;
  private baseUrl: string;

  constructor(configService: ConfigService) {
    super(configService, 'KrakenConnector');
    this.apiKey = configService.get<string>('KRAKEN_API_KEY') || '';
    this.apiSecret = configService.get<string>('KRAKEN_API_SECRET') || '';
    this.baseUrl = configService.get<string>('KRAKEN_API_URL') || 'https://api.kraken.com';
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to Kraken...');
    try {
      const response = await fetch(`${this.baseUrl}/0/public/Time`);
      const data = await response.json();
      if (data.error.length === 0) {
        this.logger.log('Successfully connected to Kraken');
      } else {
        throw new Error('Kraken API time check failed');
      }
    } catch (error) {
      this.logger.error('Failed to connect to Kraken:', error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from Kraken...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    try {
      const krakenSymbol = this.normalizeSymbolForKraken(symbol);
      const response = await fetch(
        `${this.baseUrl}/0/public/Depth?pair=${krakenSymbol}&count=100`
      );
      const data = await response.json();
      
      const pairKey = Object.keys(data.result)[0];
      const orderBook = data.result[pairKey];

      const bids = orderBook.bids.map(([price, amount, timestamp]: [string, string, string]) => ({
        price,
        amount,
        timestamp: parseInt(timestamp) * 1000,
        source: 'kraken'
      }));

      const asks = orderBook.asks.map(([price, amount, timestamp]: [string, string, string]) => ({
        price,
        amount,
        timestamp: parseInt(timestamp) * 1000,
        source: 'kraken'
      }));

      return {
        symbol,
        bids,
        asks,
        timestamp: Date.now(),
        source: 'kraken',
        spread: this.calculateSpread(bids, asks),
        depth: {
          bids: this.calculateDepth(bids),
          asks: this.calculateDepth(asks)
        }
      };
    } catch (error) {
      this.logger.error(`Failed to get order book for ${symbol}:`, error);
      throw error;
    }
  }

  async executeOrder(order: OrderRequest): Promise<TradeExecution> {
    const orderId = this.generateOrderId();
    
    return {
      id: orderId,
      orderId: order.id,
      source: 'kraken',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: order.price || '0',
      fee: (parseFloat(order.amount) * 0.0026).toString(),
      status: 'filled',
      filledAmount: order.amount,
      averagePrice: order.price || '2000',
      timestamp: Date.now()
    };
  }

  async getOrderStatus(orderId: string): Promise<TradeExecution> {
    return {
      id: orderId,
      orderId: orderId.split('_')[1],
      source: 'kraken',
      symbol: '',
      side: 'buy',
      amount: '0',
      price: '0',
      fee: '0',
      status: 'filled',
      timestamp: Date.now()
    };
  }

  async getSupportedPairs(): Promise<string[]> {
    return [
      'BTC/USD', 'ETH/USD', 'USDT/USD', 'USDC/USD',
      'XRP/USD', 'ADA/USD', 'DOT/USD', 'LINK/USD'
    ];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.0016, taker: 0.0026 };
  }

  async isHealthy(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/0/public/Time`);
      const data = await response.json();
      return data.error.length === 0;
    } catch {
      return false;
    }
  }

  private normalizeSymbolForKraken(symbol: string): string {
    const symbolMap: { [key: string]: string } = {
      'BTC/USD': 'XBTUSD',
      'ETH/USD': 'ETHUSD',
      'USDT/USD': 'USDTZUSD',
      'USDC/USD': 'USDCZUSD'
    };
    return symbolMap[symbol] || symbol.replace('/', '');
  }
}
