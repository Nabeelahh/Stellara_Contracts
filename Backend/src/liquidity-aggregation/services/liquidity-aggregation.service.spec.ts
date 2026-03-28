import { Test, TestingModule } from '@nestjs/testing';
import { LiquidityAggregationService } from '../services/liquidity-aggregation.service';
import { OrderBookAggregatorService } from '../services/order-book-aggregator.service';
import { SmartOrderRouterService } from '../services/smart-order-router.service';
import { ArbitrageDetectorService } from '../services/arbitrage-detector.service';
import { PerformanceAnalyticsService } from '../services/performance-analytics.service';
import { ExchangeConnectorFactory } from '../connectors/exchange-connector-factory';

describe('LiquidityAggregationService', () => {
  let service: LiquidityAggregationService;
  let orderBookAggregator: OrderBookAggregatorService;
  let smartOrderRouter: SmartOrderRouterService;
  let arbitrageDetector: ArbitrageDetectorService;
  let performanceAnalytics: PerformanceAnalyticsService;
  let connectorFactory: ExchangeConnectorFactory;

  beforeEach(async () => {
    const mockOrderBookAggregator = {
      getAggregatedOrderBook: jest.fn(),
      getLiquiditySources: jest.fn(),
      clearCache: jest.fn(),
    };

    const mockSmartOrderRouter = {
      createExecutionPlan: jest.fn(),
      executeOrder: jest.fn(),
    };

    const mockArbitrageDetector = {
      detectArbitrageOpportunities: jest.fn(),
      getActiveOpportunities: jest.fn(),
    };

    const mockPerformanceAnalytics = {
      recordExecution: jest.fn(),
      getPerformanceMetrics: jest.fn(),
      getSourcePerformance: jest.fn(),
      getTopPerformingSources: jest.fn(),
      clearMetrics: jest.fn(),
    };

    const mockConnectorFactory = {
      initializeAllConnectors: jest.fn(),
      shutdownAllConnectors: jest.fn(),
      getAllConnectors: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LiquidityAggregationService,
        {
          provide: OrderBookAggregatorService,
          useValue: mockOrderBookAggregator,
        },
        {
          provide: SmartOrderRouterService,
          useValue: mockSmartOrderRouter,
        },
        {
          provide: ArbitrageDetectorService,
          useValue: mockArbitrageDetector,
        },
        {
          provide: PerformanceAnalyticsService,
          useValue: mockPerformanceAnalytics,
        },
        {
          provide: ExchangeConnectorFactory,
          useValue: mockConnectorFactory,
        },
      ],
    }).compile();

    service = module.get<LiquidityAggregationService>(LiquidityAggregationService);
    orderBookAggregator = module.get<OrderBookAggregatorService>(OrderBookAggregatorService);
    smartOrderRouter = module.get<SmartOrderRouterService>(SmartOrderRouterService);
    arbitrageDetector = module.get<ArbitrageDetectorService>(ArbitrageDetectorService);
    performanceAnalytics = module.get<PerformanceAnalyticsService>(PerformanceAnalyticsService);
    connectorFactory = module.get<ExchangeConnectorFactory>(ExchangeConnectorFactory);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getAggregatedOrderBook', () => {
    it('should return aggregated order book', async () => {
      const symbol = 'BTC/USDT';
      const mockOrderBook = {
        symbol,
        bids: [{ price: '50000', amount: '1.5', timestamp: Date.now(), source: 'binance' }],
        asks: [{ price: '50100', amount: '1.2', timestamp: Date.now(), source: 'binance' }],
        timestamp: Date.now(),
        source: 'aggregated',
        spread: '100',
        depth: { bids: {}, asks: {} },
        sources: ['binance'],
        totalVolume: { bid: '1.5', ask: '1.2' },
        weightedSpread: '100',
        liquidityDistribution: {},
      };

      jest.spyOn(orderBookAggregator, 'getAggregatedOrderBook').mockResolvedValue(mockOrderBook);

      const result = await service.getAggregatedOrderBook(symbol);

      expect(orderBookAggregator.getAggregatedOrderBook).toHaveBeenCalledWith(symbol);
      expect(result).toEqual(mockOrderBook);
    });

    it('should handle errors when getting order book', async () => {
      const symbol = 'BTC/USDT';
      jest.spyOn(orderBookAggregator, 'getAggregatedOrderBook').mockRejectedValue(new Error('Network error'));

      await expect(service.getAggregatedOrderBook(symbol)).rejects.toThrow('Network error');
    });
  });

  describe('createExecutionPlan', () => {
    it('should create execution plan for order', async () => {
      const order = {
        id: 'order-1',
        symbol: 'BTC/USDT',
        side: 'buy' as const,
        amount: '2.0',
        type: 'market' as const,
        userId: 'user-1',
      };

      const mockExecutionPlan = {
        orderId: order.id,
        splits: [{
          source: 'binance',
          amount: '2.0',
          expectedSlippage: 0.001,
          fee: '0.002',
          estimatedExecutionTime: 100,
        }],
        totalExpectedSlippage: 0.001,
        totalFees: '0.002',
        estimatedExecutionTime: 100,
        confidence: 0.95,
      };

      jest.spyOn(smartOrderRouter, 'createExecutionPlan').mockResolvedValue(mockExecutionPlan);

      const result = await service.createExecutionPlan(order);

      expect(smartOrderRouter.createExecutionPlan).toHaveBeenCalledWith(order);
      expect(result).toEqual(mockExecutionPlan);
    });
  });

  describe('executeOrder', () => {
    it('should execute order and record metrics', async () => {
      const order = {
        id: 'order-1',
        symbol: 'BTC/USDT',
        side: 'buy' as const,
        amount: '2.0',
        type: 'market' as const,
        userId: 'user-1',
      };

      const mockExecutionPlan = {
        orderId: order.id,
        splits: [{
          source: 'binance',
          amount: '2.0',
          expectedSlippage: 0.001,
          fee: '0.002',
          estimatedExecutionTime: 100,
        }],
        totalExpectedSlippage: 0.001,
        totalFees: '0.002',
        estimatedExecutionTime: 100,
        confidence: 0.95,
      };

      const mockExecutions = [{
        id: 'exec-1',
        orderId: order.id,
        source: 'binance',
        symbol: order.symbol,
        side: order.side,
        amount: order.amount,
        price: '50000',
        fee: '0.002',
        status: 'filled' as const,
        filledAmount: '2.0',
        averagePrice: '50000',
        timestamp: Date.now(),
      }];

      jest.spyOn(smartOrderRouter, 'createExecutionPlan').mockResolvedValue(mockExecutionPlan);
      jest.spyOn(smartOrderRouter, 'executeOrder').mockResolvedValue(mockExecutions);
      jest.spyOn(performanceAnalytics, 'recordExecution').mockResolvedValue();

      const result = await service.executeOrder(order);

      expect(smartOrderRouter.createExecutionPlan).toHaveBeenCalledWith(order);
      expect(smartOrderRouter.executeOrder).toHaveBeenCalledWith(order, mockExecutionPlan);
      expect(performanceAnalytics.recordExecution).toHaveBeenCalledTimes(mockExecutions.length);
      expect(result).toEqual(mockExecutions);
    });
  });

  describe('getSystemHealth', () => {
    it('should return system health status', async () => {
      const mockConnectors = [
        { isHealthy: jest.fn().mockResolvedValue(true) },
        { isHealthy: jest.fn().mockResolvedValue(true) },
      ];

      const mockMetrics = [{
        source: 'binance',
        symbol: 'BTC/USDT',
        latency: { p50: 50, p95: 100, p99: 150 },
        fillRate: 0.99,
        averageSlippage: 0.001,
        errorRate: 0.01,
        volume: '1000',
        revenue: '1.0',
        timestamp: Date.now(),
      }];

      jest.spyOn(connectorFactory, 'getAllConnectors').mockReturnValue(mockConnectors as any);
      jest.spyOn(performanceAnalytics, 'getPerformanceMetrics').mockResolvedValue(mockMetrics);

      const result = await service.getSystemHealth();

      expect(result).toEqual({
        status: 'healthy',
        activeConnectors: 2,
        totalConnectors: 2,
        averageLatency: 100,
        lastUpdate: expect.any(Number),
      });
    });

    it('should return unhealthy status when no connectors are healthy', async () => {
      const mockConnectors = [
        { isHealthy: jest.fn().mockResolvedValue(false) },
        { isHealthy: jest.fn().mockResolvedValue(false) },
      ];

      jest.spyOn(connectorFactory, 'getAllConnectors').mockReturnValue(mockConnectors as any);
      jest.spyOn(performanceAnalytics, 'getPerformanceMetrics').mockResolvedValue([]);

      const result = await service.getSystemHealth();

      expect(result.status).toBe('unhealthy');
      expect(result.activeConnectors).toBe(0);
      expect(result.totalConnectors).toBe(2);
    });
  });
});
