import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class CoinbaseConnector extends BaseExchangeConnector {
  private apiKey: string;
  private apiSecret: string;
  private baseUrl: string;

  constructor(configService: ConfigService) {
    super(configService, 'CoinbaseConnector');
    this.apiKey = configService.get<string>('COINBASE_API_KEY') || '';
    this.apiSecret = configService.get<string>('COINBASE_API_SECRET') || '';
    this.baseUrl = configService.get<string>('COINBASE_API_URL') || 'https://api.exchange.coinbase.com';
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to Coinbase...');
    try {
      const response = await fetch(`${this.baseUrl}/time`);
      if (response.ok) {
        this.logger.log('Successfully connected to Coinbase');
      } else {
        throw new Error('Coinbase API time check failed');
      }
    } catch (error) {
      this.logger.error('Failed to connect to Coinbase:', error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from Coinbase...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    try {
      const response = await fetch(
        `${this.baseUrl}/products/${this.normalizeSymbol(symbol)}/book?level=2`
      );
      const data = await response.json();

      const bids = data.bids.map(([price, amount, _]: [string, string, string]) => ({
        price,
        amount,
        timestamp: Date.now(),
        source: 'coinbase'
      }));

      const asks = data.asks.map(([price, amount, _]: [string, string, string]) => ({
        price,
        amount,
        timestamp: Date.now(),
        source: 'coinbase'
      }));

      return {
        symbol,
        bids,
        asks,
        timestamp: Date.now(),
        source: 'coinbase',
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
      source: 'coinbase',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: order.price || '0',
      fee: (parseFloat(order.amount) * 0.005).toString(),
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
      source: 'coinbase',
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
      'BTC/USD', 'ETH/USD', 'SOL/USD', 'ADA/USD',
      'DOT/USD', 'LINK/USD', 'UNI/USD', 'AAVE/USD'
    ];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.005, taker: 0.005 };
  }

  async isHealthy(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/time`);
      return response.ok;
    } catch {
      return false;
    }
  }
}
