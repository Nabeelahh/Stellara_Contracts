export interface LiquiditySource {
  id: string;
  name: string;
  type: 'dex' | 'cex';
  isActive: boolean;
  priority: number;
  fees: {
    maker: number;
    taker: number;
  };
  latency: number;
  reliability: number;
  supportedPairs: string[];
}

export interface OrderBookLevel {
  price: string;
  amount: string;
  timestamp: number;
  source: string;
}

export interface NormalizedOrderBook {
  symbol: string;
  bids: OrderBookLevel[];
  asks: OrderBookLevel[];
  timestamp: number;
  source: string;
  spread: string;
  depth: {
    bids: { [price: string]: string };
    asks: { [price: string]: string };
  };
}

export interface AggregatedOrderBook {
  symbol: string;
  bids: OrderBookLevel[];
  asks: OrderBookLevel[];
  timestamp: number;
  sources: string[];
  totalVolume: {
    bid: string;
    ask: string;
  };
  weightedSpread: string;
  liquidityDistribution: {
    [source: string]: {
      bidVolume: string;
      askVolume: string;
      percentage: number;
    };
  };
}

export interface OrderRequest {
  id: string;
  symbol: string;
  side: 'buy' | 'sell';
  amount: string;
  type: 'market' | 'limit';
  price?: string;
  timeInForce?: 'IOC' | 'FOK' | 'GTC';
  userId: string;
  maxSlippage?: number;
  minFillAmount?: string;
}

export interface OrderSplit {
  source: string;
  amount: string;
  price?: string;
  expectedSlippage: number;
  fee: string;
  estimatedExecutionTime: number;
}

export interface ExecutionPlan {
  orderId: string;
  splits: OrderSplit[];
  totalExpectedSlippage: number;
  totalFees: string;
  estimatedExecutionTime: number;
  confidence: number;
}

export interface TradeExecution {
  id: string;
  orderId: string;
  source: string;
  symbol: string;
  side: 'buy' | 'sell';
  amount: string;
  price: string;
  fee: string;
  status: 'pending' | 'filled' | 'failed' | 'partial';
  filledAmount?: string;
  averagePrice?: string;
  timestamp: number;
  txHash?: string;
  errorMessage?: string;
}

export interface ArbitrageOpportunity {
  id: string;
  symbol: string;
  buySource: string;
  sellSource: string;
  buyPrice: string;
  sellPrice: string;
  profit: string;
  profitPercentage: number;
  volume: string;
  timestamp: number;
  confidence: number;
  estimatedExecutionTime: number;
}

export interface PerformanceMetrics {
  source: string;
  symbol: string;
  latency: {
    p50: number;
    p95: number;
    p99: number;
  };
  fillRate: number;
  averageSlippage: number;
  errorRate: number;
  volume: string;
  revenue: string;
  timestamp: number;
}

export interface LiquidityAggregatorConfig {
  maxSourcesPerOrder: number;
  minLiquidityThreshold: string;
  maxSlippageThreshold: number;
  orderTimeoutMs: number;
  retryAttempts: number;
  circuitBreakerThreshold: number;
  updateIntervalMs: number;
  arbitrageEnabled: boolean;
  performanceTrackingEnabled: boolean;
}

export enum ExchangeType {
  UNISWAP = 'uniswap',
  SUSHISWAP = 'sushiswap',
  CURVE = 'curve',
  BALANCER = 'balancer',
  BINANCE = 'binance',
  COINBASE = 'coinbase',
  KRAKEN = 'kraken',
}

export interface ExchangeConnector {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  getOrderBook(symbol: string): Promise<NormalizedOrderBook>;
  executeOrder(order: OrderRequest): Promise<TradeExecution>;
  getOrderStatus(orderId: string): Promise<TradeExecution>;
  getSupportedPairs(): Promise<string[]>;
  getFees(): Promise<{ maker: number; taker: number }>;
  isHealthy(): Promise<boolean>;
}
