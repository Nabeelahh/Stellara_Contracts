import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class BinanceConnector extends BaseExchangeConnector {
  private apiKey: string;
  private apiSecret: string;
  private baseUrl: string;

  constructor(configService: ConfigService) {
    super(configService, 'BinanceConnector');
    this.apiKey = configService.get<string>('BINANCE_API_KEY') || '';
    this.apiSecret = configService.get<string>('BINANCE_API_SECRET') || '';
    this.baseUrl = configService.get<string>('BINANCE_API_URL') || 'https://api.binance.com';
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to Binance...');
    try {
      const response = await fetch(`${this.baseUrl}/api/v3/ping`);
      if (response.ok) {
        this.logger.log('Successfully connected to Binance');
      } else {
        throw new Error('Binance API ping failed');
      }
    } catch (error) {
      this.logger.error('Failed to connect to Binance:', error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from Binance...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    try {
      const response = await fetch(
        `${this.baseUrl}/api/v3/depth?symbol=${this.normalizeSymbol(symbol)}&limit=100`
      );
      const data = await response.json();

      const bids = data.bids.map(([price, amount]: [string, string]) => ({
        price,
        amount,
        timestamp: Date.now(),
        source: 'binance'
      }));

      const asks = data.asks.map(([price, amount]: [string, string]) => ({
        price,
        amount,
        timestamp: Date.now(),
        source: 'binance'
      }));

      return {
        symbol,
        bids,
        asks,
        timestamp: Date.now(),
        source: 'binance',
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
      source: 'binance',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: order.price || '0',
      fee: (parseFloat(order.amount) * 0.001).toString(),
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
      source: 'binance',
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
      'BTC/USDT', 'ETH/USDT', 'BNB/USDT', 'ADA/USDT', 
      'XRP/USDT', 'SOL/USDT', 'DOT/USDT', 'DOGE/USDT'
    ];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.001, taker: 0.001 };
  }

  async isHealthy(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/v3/ping`);
      return response.ok;
    } catch {
      return false;
    }
  }
}
