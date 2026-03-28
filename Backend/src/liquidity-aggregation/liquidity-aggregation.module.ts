import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisModule } from '../redis/redis.module';
import { MonitoringModule } from '../monitoring/monitoring.module';
import { AnalyticsModule } from '../analytics/analytics.module';
import { CircuitBreakerModule } from '../circuit-breaker/circuit-breaker.module';
import { LiquidityAggregationService } from './services/liquidity-aggregation.service';
import { OrderBookAggregatorService } from './services/order-book-aggregator.service';
import { SmartOrderRouterService } from './services/smart-order-router.service';
import { ArbitrageDetectorService } from './services/arbitrage-detector.service';
import { PerformanceAnalyticsService } from './services/performance-analytics.service';
import { ExchangeConnectorFactory } from './connectors/exchange-connector-factory';
import { UniswapConnector } from './connectors/dex/uniswap.connector';
import { SushiswapConnector } from './connectors/dex/sushiswap.connector';
import { CurveConnector } from './connectors/dex/curve.connector';
import { BalancerConnector } from './connectors/dex/balancer.connector';
import { BinanceConnector } from './connectors/cex/binance.connector';
import { CoinbaseConnector } from './connectors/cex/coinbase.connector';
import { KrakenConnector } from './connectors/cex/kraken.connector';
import { LiquidityAggregationController } from './controllers/liquidity-aggregation.controller';
import { LiquidityAggregationGateway } from './gateways/liquidity-aggregation.gateway';
import { LiquidityAggregationRepository } from './repositories/liquidity-aggregation.repository';

@Module({
  imports: [
    ConfigModule,
    RedisModule,
    MonitoringModule,
    AnalyticsModule,
    CircuitBreakerModule,
  ],
  controllers: [LiquidityAggregationController],
  providers: [
    LiquidityAggregationService,
    OrderBookAggregatorService,
    SmartOrderRouterService,
    ArbitrageDetectorService,
    PerformanceAnalyticsService,
    ExchangeConnectorFactory,
    UniswapConnector,
    SushiswapConnector,
    CurveConnector,
    BalancerConnector,
    BinanceConnector,
    CoinbaseConnector,
    KrakenConnector,
    LiquidityAggregationRepository,
    LiquidityAggregationGateway,
  ],
  exports: [
    LiquidityAggregationService,
    OrderBookAggregatorService,
    SmartOrderRouterService,
    ArbitrageDetectorService,
    PerformanceAnalyticsService,
    ExchangeConnectorFactory,
    LiquidityAggregationRepository,
  ],
})
export class LiquidityAggregationModule {}
