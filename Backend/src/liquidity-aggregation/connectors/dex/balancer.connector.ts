import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class BalancerConnector extends BaseExchangeConnector {
  constructor(configService: ConfigService) {
    super(configService, 'BalancerConnector');
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to Balancer...');
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from Balancer...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    const mockBids = Array.from({ length: 15 }, (_, i) => ({
      price: (2000 - i * 0.08).toString(),
      amount: (Math.random() * 500).toString(),
      timestamp: Date.now(),
      source: 'balancer'
    }));

    const mockAsks = Array.from({ length: 15 }, (_, i) => ({
      price: (2000 + i * 0.08).toString(),
      amount: (Math.random() * 500).toString(),
      timestamp: Date.now(),
      source: 'balancer'
    }));

    return {
      symbol,
      bids: mockBids,
      asks: mockAsks,
      timestamp: Date.now(),
      source: 'balancer',
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
      source: 'balancer',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: '2000',
      fee: (parseFloat(order.amount) * 0.001).toString(),
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
      source: 'balancer',
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
    return ['ETH/USDC', 'ETH/USDT', 'WBTC/ETH', 'BAL/WETH'];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.0001, taker: 0.001 };
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }
}
