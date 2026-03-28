import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class CurveConnector extends BaseExchangeConnector {
  constructor(configService: ConfigService) {
    super(configService, 'CurveConnector');
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to Curve...');
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from Curve...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    const mockBids = Array.from({ length: 10 }, (_, i) => ({
      price: (2000 - i * 0.05).toString(),
      amount: (Math.random() * 1000).toString(),
      timestamp: Date.now(),
      source: 'curve'
    }));

    const mockAsks = Array.from({ length: 10 }, (_, i) => ({
      price: (2000 + i * 0.05).toString(),
      amount: (Math.random() * 1000).toString(),
      timestamp: Date.now(),
      source: 'curve'
    }));

    return {
      symbol,
      bids: mockBids,
      asks: mockAsks,
      timestamp: Date.now(),
      source: 'curve',
      spread: this.calculateSpread(mockBids, mockAsks),
      depth: {
        bids: this.calculateDepth(mockBids),
        asks: this.calculateDepth(mockAsks)
      }
    };
  }

  async executeOrder(order: OrderRequest): Promise<TradeExecution> {
    return {
      id: this.generateOrderId(),
      orderId: order.id,
      source: 'curve',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: '2000',
      fee: (parseFloat(order.amount) * 0.0004).toString(),
      status: 'filled',
      filledAmount: order.amount,
      averagePrice: '2000',
      timestamp: Date.now()
    };
  }

  async getOrderStatus(orderId: string): Promise<TradeExecution> {
    return {
      id: orderId,
      orderId: orderId.split('_')[1],
      source: 'curve',
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
    return ['USDC/USDT', 'DAI/USDC', 'WBTC/renBTC'];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.0002, taker: 0.0004 };
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }
}
