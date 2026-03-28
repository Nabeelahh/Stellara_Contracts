import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class SushiswapConnector extends BaseExchangeConnector {
  constructor(configService: ConfigService) {
    super(configService, 'SushiswapConnector');
  }

  async connect(): Promise<void> {
    this.logger.log('Connecting to SushiSwap...');
  }

  async disconnect(): Promise<void> {
    this.logger.log('Disconnecting from SushiSwap...');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    const mockBids = Array.from({ length: 10 }, (_, i) => ({
      price: (2000 - i * 0.1).toString(),
      amount: (Math.random() * 100).toString(),
      timestamp: Date.now(),
      source: 'sushiswap'
    }));

    const mockAsks = Array.from({ length: 10 }, (_, i) => ({
      price: (2000 + i * 0.1).toString(),
      amount: (Math.random() * 100).toString(),
      timestamp: Date.now(),
      source: 'sushiswap'
    }));

    return {
      symbol,
      bids: mockBids,
      asks: mockAsks,
      timestamp: Date.now(),
      source: 'sushiswap',
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
      source: 'sushiswap',
      symbol: order.symbol,
      side: order.side,
      amount: order.amount,
      price: '2000',
      fee: (parseFloat(order.amount) * 0.003).toString(),
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
      source: 'sushiswap',
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
    return ['ETH/USDC', 'ETH/USDT', 'WBTC/ETH'];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return { maker: 0.0005, taker: 0.0030 };
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }
}
