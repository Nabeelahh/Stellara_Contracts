import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import { 
  AggregatedOrderBook, 
  ArbitrageOpportunity,
  PerformanceMetrics 
} from '../interfaces/liquidity-aggregation.interface';
import { LiquidityAggregationService } from '../services/liquidity-aggregation.service';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: 'liquidity-aggregation',
})
export class LiquidityAggregationGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(LiquidityAggregationGateway.name);
  private readonly subscribers = new Map<string, Set<string>>();

  constructor(private liquidityAggregationService: LiquidityAggregationService) {}

  handleConnection(client: Socket): void {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket): void {
    this.logger.log(`Client disconnected: ${client.id}`);
    this.cleanupSubscriptions(client.id);
  }

  @SubscribeMessage('subscribe-orderbook')
  async handleSubscribeOrderBook(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { symbol: string },
  ): Promise<void> {
    const { symbol } = data;
    
    if (!this.subscribers.has(symbol)) {
      this.subscribers.set(symbol, new Set());
    }
    
    this.subscribers.get(symbol)!.add(client.id);
    
    try {
      const orderBook = await this.liquidityAggregationService.getAggregatedOrderBook(symbol);
      client.emit('orderbook-update', { symbol, data: orderBook });
      
      this.startOrderBookStreaming(symbol);
    } catch (error) {
      client.emit('error', { message: `Failed to subscribe to ${symbol}` });
    }
  }

  @SubscribeMessage('unsubscribe-orderbook')
  handleUnsubscribeOrderBook(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { symbol: string },
  ): void {
    const { symbol } = data;
    
    if (this.subscribers.has(symbol)) {
      this.subscribers.get(symbol)!.delete(client.id);
      
      if (this.subscribers.get(symbol)!.size === 0) {
        this.subscribers.delete(symbol);
      }
    }
  }

  @SubscribeMessage('subscribe-arbitrage')
  async handleSubscribeArbitrage(@ConnectedSocket() client: Socket): Promise<void> {
    client.join('arbitrage-updates');
    
    try {
      const opportunities = await this.liquidityAggregationService.detectArbitrageOpportunities();
      client.emit('arbitrage-update', opportunities);
    } catch (error) {
      client.emit('error', { message: 'Failed to subscribe to arbitrage updates' });
    }
  }

  @SubscribeMessage('get-performance-metrics')
  async handleGetPerformanceMetrics(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { source?: string; symbol?: string },
  ): Promise<void> {
    try {
      const metrics = await this.liquidityAggregationService.getPerformanceMetrics(
        data.source,
        data.symbol,
      );
      client.emit('performance-metrics', metrics);
    } catch (error) {
      client.emit('error', { message: 'Failed to get performance metrics' });
    }
  }

  @SubscribeMessage('get-system-health')
  async handleGetSystemHealth(@ConnectedSocket() client: Socket): Promise<void> {
    try {
      const health = await this.liquidityAggregationService.getSystemHealth();
      client.emit('system-health', health);
    } catch (error) {
      client.emit('error', { message: 'Failed to get system health' });
    }
  }

  private async startOrderBookStreaming(symbol: string): Promise<void> {
    const interval = setInterval(async () => {
      try {
        const orderBook = await this.liquidityAggregationService.getAggregatedOrderBook(symbol);
        
        this.server.to(symbol).emit('orderbook-update', {
          symbol,
          data: orderBook,
          timestamp: Date.now(),
        });
      } catch (error) {
        this.logger.error(`Failed to stream order book for ${symbol}:`, error);
      }
    }, 1000);

    setTimeout(() => {
      if (this.subscribers.has(symbol)) {
        clearInterval(interval);
      }
    }, 300000);
  }

  private cleanupSubscriptions(clientId: string): void {
    for (const [symbol, subscribers] of this.subscribers.entries()) {
      subscribers.delete(clientId);
      
      if (subscribers.size === 0) {
        this.subscribers.delete(symbol);
      }
    }
  }

  broadcastArbitrageOpportunity(opportunity: ArbitrageOpportunity): void {
    this.server.to('arbitrage-updates').emit('arbitrage-opportunity', opportunity);
  }

  broadcastPerformanceUpdate(metrics: PerformanceMetrics): void {
    this.server.emit('performance-update', metrics);
  }

  broadcastSystemHealth(health: any): void {
    this.server.emit('system-health-update', health);
  }
}
