import { Injectable, Logger } from '@nestjs/common';
import { 
  OrderRequest, 
  ExecutionPlan, 
  TradeExecution, 
  AggregatedOrderBook, 
  ArbitrageOpportunity,
  LiquiditySource,
  PerformanceMetrics
} from '../interfaces/liquidity-aggregation.interface';
import { OrderBookAggregatorService } from './order-book-aggregator.service';
import { SmartOrderRouterService } from './smart-order-router.service';
import { ArbitrageDetectorService } from './arbitrage-detector.service';
import { PerformanceAnalyticsService } from './performance-analytics.service';
import { ExchangeConnectorFactory } from '../connectors/exchange-connector-factory';

@Injectable()
export class LiquidityAggregationService {
  private readonly logger = new Logger(LiquidityAggregationService.name);

  constructor(
    private orderBookAggregator: OrderBookAggregatorService,
    private smartOrderRouter: SmartOrderRouterService,
    private arbitrageDetector: ArbitrageDetectorService,
    private performanceAnalytics: PerformanceAnalyticsService,
    private exchangeConnectorFactory: ExchangeConnectorFactory,
  ) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.exchangeConnectorFactory.initializeAllConnectors();
      this.logger.log('Liquidity aggregation service initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize liquidity aggregation service:', error);
      throw error;
    }
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.exchangeConnectorFactory.shutdownAllConnectors();
      this.logger.log('Liquidity aggregation service shutdown successfully');
    } catch (error) {
      this.logger.error('Failed to shutdown liquidity aggregation service:', error);
    }
  }

  async getAggregatedOrderBook(symbol: string): Promise<AggregatedOrderBook> {
    try {
      const startTime = Date.now();
      const orderBook = await this.orderBookAggregator.getAggregatedOrderBook(symbol);
      const latency = Date.now() - startTime;

      this.logger.log(`Retrieved aggregated order book for ${symbol} in ${latency}ms`);
      
      return orderBook;
    } catch (error) {
      this.logger.error(`Failed to get aggregated order book for ${symbol}:`, error);
      throw error;
    }
  }

  async createExecutionPlan(order: OrderRequest): Promise<ExecutionPlan> {
    try {
      const startTime = Date.now();
      const executionPlan = await this.smartOrderRouter.createExecutionPlan(order);
      const latency = Date.now() - startTime;

      this.logger.log(
        `Created execution plan for order ${order.id} in ${latency}ms: ` +
        `${executionPlan.splits.length} splits, ${(executionPlan.totalExpectedSlippage * 100).toFixed(3)}% slippage`
      );

      if (executionPlan.confidence < 0.7) {
        this.logger.warn(`Low confidence execution plan for order ${order.id}: ${executionPlan.confidence}`);
      }

      return executionPlan;
    } catch (error) {
      this.logger.error(`Failed to create execution plan for order ${order.id}:`, error);
      throw error;
    }
  }

  async executeOrder(order: OrderRequest): Promise<TradeExecution[]> {
    try {
      const startTime = Date.now();
      
      const executionPlan = await this.createExecutionPlan(order);
      const executions = await this.smartOrderRouter.executeOrder(order, executionPlan);
      const totalLatency = Date.now() - startTime;

      const totalAmount = executions.reduce((sum, exec) => 
        sum + parseFloat(exec.filledAmount || '0'), 0
      );
      const totalFees = executions.reduce((sum, exec) => 
        sum + parseFloat(exec.fee), 0
      );
      const fillRate = totalAmount / parseFloat(order.amount);

      this.logger.log(
        `Executed order ${order.id} in ${totalLatency}ms: ` +
        `${executions.length}/${executionPlan.splits.length} executions, ` +
        `${(fillRate * 100).toFixed(2)}% fill rate, $${totalFees.toFixed(2)} fees`
      );

      for (const execution of executions) {
        await this.performanceAnalytics.recordExecution(execution);
      }

      return executions;
    } catch (error) {
      this.logger.error(`Failed to execute order ${order.id}:`, error);
      throw error;
    }
  }

  async detectArbitrageOpportunities(symbol?: string): Promise<ArbitrageOpportunity[]> {
    try {
      const opportunities = symbol 
        ? await this.arbitrageDetector.detectArbitrageOpportunities(symbol)
        : await this.arbitrageDetector.getActiveOpportunities();

      this.logger.log(`Found ${opportunities.length} arbitrage opportunities${symbol ? ` for ${symbol}` : ''}`);
      
      return opportunities;
    } catch (error) {
      this.logger.error('Failed to detect arbitrage opportunities:', error);
      return [];
    }
  }

  async getLiquiditySources(): Promise<LiquiditySource[]> {
    try {
      const sources = await this.orderBookAggregator.getLiquiditySources();
      const performanceData = await this.performanceAnalytics.getSourcePerformance(sources);

      return sources.map(source => ({
        ...source,
        latency: performanceData[source.id]?.latency.p50 || source.latency,
        reliability: performanceData[source.id]?.fillRate || source.reliability
      }));
    } catch (error) {
      this.logger.error('Failed to get liquidity sources:', error);
      throw error;
    }
  }

  async getPerformanceMetrics(source?: string, symbol?: string): Promise<PerformanceMetrics[]> {
    try {
      return await this.performanceAnalytics.getPerformanceMetrics(source, symbol);
    } catch (error) {
      this.logger.error('Failed to get performance metrics:', error);
      return [];
    }
  }

  async getTopPerformingSources(limit: number = 5): Promise<LiquiditySource[]> {
    try {
      return await this.performanceAnalytics.getTopPerformingSources(limit);
    } catch (error) {
      this.logger.error('Failed to get top performing sources:', error);
      return [];
    }
  }

  async getSystemHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    activeConnectors: number;
    totalConnectors: number;
    averageLatency: number;
    lastUpdate: number;
  }> {
    try {
      const connectors = this.exchangeConnectorFactory.getAllConnectors();
      const healthChecks = await Promise.allSettled(
        connectors.map(connector => connector.isHealthy())
      );

      const activeConnectors = healthChecks.filter(
        result => result.status === 'fulfilled' && result.value
      ).length;

      const totalConnectors = connectors.length;
      const healthRatio = activeConnectors / totalConnectors;

      let status: 'healthy' | 'degraded' | 'unhealthy';
      if (healthRatio >= 0.8) {
        status = 'healthy';
      } else if (healthRatio >= 0.5) {
        status = 'degraded';
      } else {
        status = 'unhealthy';
      }

      const metrics = await this.performanceAnalytics.getPerformanceMetrics();
      const averageLatency = metrics.length > 0 
        ? metrics.reduce((sum, m) => sum + m.latency.p95, 0) / metrics.length
        : 0;

      return {
        status,
        activeConnectors,
        totalConnectors,
        averageLatency,
        lastUpdate: Date.now()
      };
    } catch (error) {
      this.logger.error('Failed to get system health:', error);
      return {
        status: 'unhealthy',
        activeConnectors: 0,
        totalConnectors: 0,
        averageLatency: 0,
        lastUpdate: Date.now()
      };
    }
  }

  async refreshOrderBook(symbol: string): Promise<void> {
    try {
      await this.orderBookAggregator.clearCache(symbol);
      await this.orderBookAggregator.getAggregatedOrderBook(symbol);
      this.logger.log(`Refreshed order book for ${symbol}`);
    } catch (error) {
      this.logger.error(`Failed to refresh order book for ${symbol}:`, error);
      throw error;
    }
  }

  async clearAllCaches(): Promise<void> {
    try {
      await this.orderBookAggregator.clearCache();
      await this.performanceAnalytics.clearMetrics();
      this.logger.log('Cleared all caches');
    } catch (error) {
      this.logger.error('Failed to clear caches:', error);
      throw error;
    }
  }

  async getSupportedSymbols(): Promise<string[]> {
    try {
      const sources = await this.getLiquiditySources();
      const allSymbols = new Set<string>();

      for (const source of sources) {
        for (const pair of source.supportedPairs) {
          allSymbols.add(pair);
        }
      }

      return Array.from(allSymbols).sort();
    } catch (error) {
      this.logger.error('Failed to get supported symbols:', error);
      return [];
    }
  }
}
