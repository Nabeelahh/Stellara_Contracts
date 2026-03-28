import { Injectable, Logger } from '@nestjs/common';
import { 
  OrderRequest, 
  ExecutionPlan, 
  OrderSplit, 
  TradeExecution,
  AggregatedOrderBook,
  LiquiditySource 
} from '../interfaces/liquidity-aggregation.interface';
import { OrderBookAggregatorService } from './order-book-aggregator.service';
import { ExchangeConnectorFactory } from '../connectors/exchange-connector-factory';

@Injectable()
export class SmartOrderRouterService {
  private readonly logger = new Logger(SmartOrderRouterService.name);
  private readonly MAX_SOURCES_PER_ORDER = 5;
  private readonly MIN_LIQUIDITY_THRESHOLD = 1000;
  private readonly MAX_SLIPPAGE_THRESHOLD = 0.05;

  constructor(
    private orderBookAggregator: OrderBookAggregatorService,
    private exchangeConnectorFactory: ExchangeConnectorFactory,
  ) {}

  async createExecutionPlan(order: OrderRequest): Promise<ExecutionPlan> {
    try {
      this.logger.log(`Creating execution plan for order ${order.id}: ${order.side} ${order.amount} ${order.symbol}`);

      const aggregatedOrderBook = await this.orderBookAggregator.getAggregatedOrderBook(order.symbol);
      const liquiditySources = await this.orderBookAggregator.getLiquiditySources();
      
      const orderAmount = parseFloat(order.amount);
      const isLargeOrder = orderAmount > 10000;

      let splits: OrderSplit[];

      if (isLargeOrder) {
        splits = await this.splitLargeOrder(order, aggregatedOrderBook, liquiditySources);
      } else {
        splits = await this.routeSmallOrder(order, aggregatedOrderBook, liquiditySources);
      }

      const totalExpectedSlippage = this.calculateTotalSlippage(splits, order.side);
      const totalFees = this.calculateTotalFees(splits);
      const estimatedExecutionTime = Math.max(...splits.map(s => s.estimatedExecutionTime));
      const confidence = this.calculateConfidence(splits, liquiditySources);

      const executionPlan: ExecutionPlan = {
        orderId: order.id,
        splits,
        totalExpectedSlippage,
        totalFees,
        estimatedExecutionTime,
        confidence
      };

      this.logger.log(`Execution plan created for order ${order.id}: ${splits.length} splits, ${totalExpectedSlippage * 100}% slippage`);
      
      return executionPlan;
    } catch (error) {
      this.logger.error(`Failed to create execution plan for order ${order.id}:`, error);
      throw error;
    }
  }

  async executeOrder(order: OrderRequest, executionPlan: ExecutionPlan): Promise<TradeExecution[]> {
    const executions: TradeExecution[] = [];
    const failedSplits: OrderSplit[] = [];

    this.logger.log(`Executing order ${order.id} with ${executionPlan.splits.length} splits`);

    for (const split of executionPlan.splits) {
      try {
        const connector = this.exchangeConnectorFactory.getConnector(split.source as any);
        const splitOrder: OrderRequest = {
          ...order,
          amount: split.amount,
          price: split.price
        };

        const execution = await connector.executeOrder(splitOrder);
        executions.push(execution);

        this.logger.log(`Successfully executed split on ${split.source}: ${split.amount} at ${execution.price}`);
      } catch (error) {
        this.logger.error(`Failed to execute split on ${split.source}:`, error);
        failedSplits.push(split);
      }
    }

    if (failedSplits.length > 0) {
      await this.handleFailedSplits(order, failedSplits, executions);
    }

    return executions;
  }

  private async splitLargeOrder(
    order: OrderRequest, 
    orderBook: AggregatedOrderBook, 
    sources: LiquiditySource[]
  ): Promise<OrderSplit[]> {
    const orderAmount = parseFloat(order.amount);
    const splits: OrderSplit[] = [];
    let remainingAmount = orderAmount;

    const activeSources = sources
      .filter(s => s.isActive && s.reliability > 0.8)
      .sort((a, b) => b.priority - a.priority)
      .slice(0, this.MAX_SOURCES_PER_ORDER);

    const liquidityDistribution = this.calculateLiquidityDistribution(orderBook, activeSources);

    for (const source of activeSources) {
      if (remainingAmount <= 0) break;

      const sourceLiquidity = liquidityDistribution[source.id] || 0;
      const allocation = Math.min(
        remainingAmount * (sourceLiquidity / 100),
        remainingAmount * 0.4
      );

      if (allocation >= this.MIN_LIQUIDITY_THRESHOLD) {
        const split = await this.createOrderSplit(
          order,
          source.name.toLowerCase(),
          allocation.toString(),
          orderBook,
          source
        );

        if (split.expectedSlippage <= this.MAX_SLIPPAGE_THRESHOLD) {
          splits.push(split);
          remainingAmount -= allocation;
        }
      }
    }

    if (remainingAmount > 0 && splits.length > 0) {
      const largestSplit = splits.reduce((max, split) => 
        parseFloat(split.amount) > parseFloat(max.amount) ? split : max
      );
      
      const additionalAmount = Math.min(remainingAmount, parseFloat(largestSplit.amount) * 0.5);
      largestSplit.amount = (parseFloat(largestSplit.amount) + additionalAmount).toString();
      remainingAmount -= additionalAmount;
    }

    if (remainingAmount > 0) {
      throw new Error(`Insufficient liquidity to execute order. Remaining: ${remainingAmount}`);
    }

    return splits;
  }

  private async routeSmallOrder(
    order: OrderRequest,
    orderBook: AggregatedOrderBook,
    sources: LiquiditySource[]
  ): Promise<OrderSplit[]> {
    const bestSource = sources
      .filter(s => s.isActive)
      .sort((a, b) => {
        const aScore = (a.priority * 0.4) + ((1 - a.fees.taker) * 0.3) + (a.reliability * 0.3);
        const bScore = (b.priority * 0.4) + ((1 - b.fees.taker) * 0.3) + (b.reliability * 0.3);
        return bScore - aScore;
      })[0];

    if (!bestSource) {
      throw new Error('No active liquidity sources available');
    }

    const split = await this.createOrderSplit(
      order,
      bestSource.name.toLowerCase(),
      order.amount,
      orderBook,
      bestSource
    );

    return [split];
  }

  private async createOrderSplit(
    order: OrderRequest,
    source: string,
    amount: string,
    orderBook: AggregatedOrderBook,
    liquiditySource: LiquiditySource
  ): Promise<OrderSplit> {
    const estimatedSlippage = this.estimateSlippage(order, parseFloat(amount), orderBook);
    const fee = (parseFloat(amount) * liquiditySource.fees.taker).toString();
    const estimatedExecutionTime = liquiditySource.latency + Math.random() * 100;

    let price: string | undefined;
    
    if (order.type === 'limit' && order.price) {
      price = order.price;
    } else {
      price = this.getEstimatedPrice(order, parseFloat(amount), orderBook);
    }

    return {
      source,
      amount,
      price,
      expectedSlippage: estimatedSlippage,
      fee,
      estimatedExecutionTime
    };
  }

  private estimateSlippage(order: OrderRequest, amount: number, orderBook: AggregatedOrderBook): number {
    const levels = order.side === 'buy' ? orderBook.asks : orderBook.bids;
    let remainingAmount = amount;
    let totalCost = 0;
    let weightedPrice = 0;

    for (const level of levels) {
      if (remainingAmount <= 0) break;

      const levelAmount = Math.min(remainingAmount, parseFloat(level.amount));
      totalCost += levelAmount * parseFloat(level.price);
      remainingAmount -= levelAmount;
    }

    if (totalCost > 0) {
      weightedPrice = totalCost / (amount - remainingAmount);
    }

    const marketPrice = order.side === 'buy' ? 
      parseFloat(orderBook.asks[0]?.price || '0') :
      parseFloat(orderBook.bids[0]?.price || '0');

    if (weightedPrice === 0 || marketPrice === 0) return 0;

    return Math.abs((weightedPrice - marketPrice) / marketPrice);
  }

  private getEstimatedPrice(order: OrderRequest, amount: number, orderBook: AggregatedOrderBook): string {
    const levels = order.side === 'buy' ? orderBook.asks : orderBook.bids;
    let remainingAmount = amount;
    let totalCost = 0;

    for (const level of levels) {
      if (remainingAmount <= 0) break;

      const levelAmount = Math.min(remainingAmount, parseFloat(level.amount));
      totalCost += levelAmount * parseFloat(level.price);
      remainingAmount -= levelAmount;
    }

    return totalCost > 0 ? (totalCost / amount).toString() : '0';
  }

  private calculateTotalSlippage(splits: OrderSplit[], side: 'buy' | 'sell'): number {
    const totalAmount = splits.reduce((sum, split) => sum + parseFloat(split.amount), 0);
    const weightedSlippage = splits.reduce((sum, split) => {
      const weight = parseFloat(split.amount) / totalAmount;
      return sum + (split.expectedSlippage * weight);
    }, 0);

    return weightedSlippage;
  }

  private calculateTotalFees(splits: OrderSplit[]): string {
    return splits.reduce((sum, split) => sum + parseFloat(split.fee), 0).toString();
  }

  private calculateConfidence(splits: OrderSplit[], sources: LiquiditySource[]): number {
    let totalConfidence = 0;
    let totalWeight = 0;

    for (const split of splits) {
      const source = sources.find(s => s.name.toLowerCase() === split.source);
      if (source) {
        const weight = parseFloat(split.amount);
        totalConfidence += source.reliability * weight;
        totalWeight += weight;
      }
    }

    return totalWeight > 0 ? totalConfidence / totalWeight : 0;
  }

  private calculateLiquidityDistribution(
    orderBook: AggregatedOrderBook, 
    sources: LiquiditySource[]
  ): { [sourceId: string]: number } {
    const distribution: { [sourceId: string]: number } = {};
    const totalLiquidity = Object.values(orderBook.liquidityDistribution)
      .reduce((sum, dist) => sum + dist.percentage, 0);

    for (const [sourceName, dist] of Object.entries(orderBook.liquidityDistribution)) {
      const source = sources.find(s => s.name.toLowerCase() === sourceName);
      if (source && source.isActive) {
        distribution[source.id] = totalLiquidity > 0 ? (dist.percentage / totalLiquidity) * 100 : 0;
      }
    }

    return distribution;
  }

  private async handleFailedSplits(
    order: OrderRequest,
    failedSplits: OrderSplit[],
    successfulExecutions: TradeExecution[]
  ): Promise<void> {
    this.logger.warn(`Handling ${failedSplits.length} failed splits for order ${order.id}`);

    const totalFailedAmount = failedSplits.reduce((sum, split) => sum + parseFloat(split.amount), 0);
    const totalExecutedAmount = successfulExecutions.reduce((sum, exec) => 
      sum + parseFloat(exec.filledAmount || '0'), 0);

    const fillPercentage = totalExecutedAmount / parseFloat(order.amount);

    if (fillPercentage < 0.5) {
      this.logger.error(`Order ${order.id} fill rate too low: ${fillPercentage * 100}%`);
      
      for (const execution of successfulExecutions) {
        try {
          await this.rollbackExecution(execution);
        } catch (error) {
          this.logger.error(`Failed to rollback execution ${execution.id}:`, error);
        }
      }

      throw new Error(`Order execution failed: insufficient fill rate (${fillPercentage * 100}%)`);
    }

    this.logger.log(`Order ${order.id} partially filled: ${fillPercentage * 100}%`);
  }

  private async rollbackExecution(execution: TradeExecution): Promise<void> {
    this.logger.log(`Rolling back execution ${execution.id}`);
  }
}
