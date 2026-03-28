import { Injectable, Logger } from '@nestjs/common';
import { ExchangeConnector, ExchangeType } from '../interfaces/liquidity-aggregation.interface';
import { UniswapConnector } from './dex/uniswap.connector';
import { SushiswapConnector } from './dex/sushiswap.connector';
import { CurveConnector } from './dex/curve.connector';
import { BalancerConnector } from './dex/balancer.connector';
import { BinanceConnector } from './cex/binance.connector';
import { CoinbaseConnector } from './cex/coinbase.connector';
import { KrakenConnector } from './cex/kraken.connector';

@Injectable()
export class ExchangeConnectorFactory {
  private readonly logger = new Logger(ExchangeConnectorFactory.name);
  private readonly connectors = new Map<ExchangeType, ExchangeConnector>();

  constructor(
    private uniswapConnector: UniswapConnector,
    private sushiswapConnector: SushiswapConnector,
    private curveConnector: CurveConnector,
    private balancerConnector: BalancerConnector,
    private binanceConnector: BinanceConnector,
    private coinbaseConnector: CoinbaseConnector,
    private krakenConnector: KrakenConnector,
  ) {
    this.initializeConnectors();
  }

  private initializeConnectors(): void {
    this.connectors.set(ExchangeType.UNISWAP, this.uniswapConnector);
    this.connectors.set(ExchangeType.SUSHISWAP, this.sushiswapConnector);
    this.connectors.set(ExchangeType.CURVE, this.curveConnector);
    this.connectors.set(ExchangeType.BALANCER, this.balancerConnector);
    this.connectors.set(ExchangeType.BINANCE, this.binanceConnector);
    this.connectors.set(ExchangeType.COINBASE, this.coinbaseConnector);
    this.connectors.set(ExchangeType.KRAKEN, this.krakenConnector);

    this.logger.log(`Initialized ${this.connectors.size} exchange connectors`);
  }

  getConnector(exchangeType: ExchangeType): ExchangeConnector {
    const connector = this.connectors.get(exchangeType);
    if (!connector) {
      throw new Error(`No connector found for exchange type: ${exchangeType}`);
    }
    return connector;
  }

  getAllConnectors(): ExchangeConnector[] {
    return Array.from(this.connectors.values());
  }

  getActiveConnectors(): ExchangeConnector[] {
    return this.getAllConnectors().filter(connector => 
      connector.isHealthy().catch(() => false)
    );
  }

  async initializeAllConnectors(): Promise<void> {
    const initPromises = this.getAllConnectors().map(async (connector) => {
      try {
        await connector.connect();
        this.logger.log(`Successfully connected to ${connector.constructor.name}`);
      } catch (error) {
        this.logger.error(`Failed to connect to ${connector.constructor.name}:`, error);
      }
    });

    await Promise.allSettled(initPromises);
  }

  async shutdownAllConnectors(): Promise<void> {
    const shutdownPromises = this.getAllConnectors().map(async (connector) => {
      try {
        await connector.disconnect();
        this.logger.log(`Successfully disconnected from ${connector.constructor.name}`);
      } catch (error) {
        this.logger.error(`Failed to disconnect from ${connector.constructor.name}:`, error);
      }
    });

    await Promise.allSettled(shutdownPromises);
  }
}
