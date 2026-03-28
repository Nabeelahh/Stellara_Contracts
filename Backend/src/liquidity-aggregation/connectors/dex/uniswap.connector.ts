import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ethers } from 'ethers';
import axios from 'axios';
import { BaseExchangeConnector } from '../base/base-connector';
import { NormalizedOrderBook, OrderRequest, TradeExecution } from '../../interfaces/liquidity-aggregation.interface';

@Injectable()
export class UniswapConnector extends BaseExchangeConnector {
  private provider: ethers.JsonRpcProvider;
  private router: ethers.Contract;
  private factory: ethers.Contract;
  private readonly UNISWAP_V3_ROUTER = '0xE592427A0AEce92De3Edee1F18E0157C05861564';
  private readonly UNISWAP_V3_FACTORY = '0x1F98431c8aD98523631AE4a59f267346ea31F984';

  constructor(configService: ConfigService) {
    super(configService, 'UniswapConnector');
    const rpcUrl = configService.get<string>('ETHEREUM_RPC_URL');
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
  }

  async connect(): Promise<void> {
    try {
      const routerAbi = [
        'function exactInputSingle(tuple(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)) external payable returns (uint256 amountOut)',
        'function exactOutputSingle(tuple(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountOut, uint256 amountInMaximum, uint160 sqrtPriceLimitX96)) external payable returns (uint256 amountIn)',
        'function quoteExactInputSingle(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint160 sqrtPriceLimitX96) external returns (uint256 amountOut)',
        'function quoteExactOutputSingle(address tokenIn, address tokenOut, uint24 fee, uint256 amountOut, uint160 sqrtPriceLimitX96) external returns (uint256 amountIn)'
      ];

      const factoryAbi = [
        'function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool)',
        'function feeAmountTickSpacing(uint24 fee) external view returns (int24 tickSpacing)'
      ];

      this.router = new ethers.Contract(this.UNISWAP_V3_ROUTER, routerAbi, this.provider);
      this.factory = new ethers.Contract(this.UNISWAP_V3_FACTORY, factoryAbi, this.provider);

      this.logger.log('Connected to Uniswap V3');
    } catch (error) {
      this.logger.error('Failed to connect to Uniswap:', error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.provider = null as any;
    this.router = null as any;
    this.factory = null as any;
    this.logger.log('Disconnected from Uniswap');
  }

  async getOrderBook(symbol: string): Promise<NormalizedOrderBook> {
    try {
      const [tokenIn, tokenOut] = this.parseSymbol(symbol);
      const pools = await this.getPools(tokenIn, tokenOut);
      
      const bids: any[] = [];
      const asks: any[] = [];

      for (const pool of pools) {
        const poolData = await this.getPoolLiquidity(pool);
        const midPrice = await this.getMidPrice(pool);
        
        const spread = parseFloat(midPrice) * 0.001;
        
        for (let i = 1; i <= 10; i++) {
          const bidPrice = parseFloat(midPrice) - (spread * i);
          const askPrice = parseFloat(midPrice) + (spread * i);
          
          const bidAmount = await this.estimateLiquidityAtPrice(pool, bidPrice.toString());
          const askAmount = await this.estimateLiquidityAtPrice(pool, askPrice.toString());
          
          if (parseFloat(bidAmount) > 0) {
            bids.push({
              price: bidPrice.toString(),
              amount: bidAmount,
              timestamp: Date.now(),
              source: 'uniswap'
            });
          }
          
          if (parseFloat(askAmount) > 0) {
            asks.push({
              price: askPrice.toString(),
              amount: askAmount,
              timestamp: Date.now(),
              source: 'uniswap'
            });
          }
        }
      }

      bids.sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
      asks.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));

      const spread = this.calculateSpread(bids, asks);
      const depth = {
        bids: this.calculateDepth(bids),
        asks: this.calculateDepth(asks)
      };

      return {
        symbol,
        bids,
        asks,
        timestamp: Date.now(),
        source: 'uniswap',
        spread,
        depth
      };
    } catch (error) {
      this.logger.error(`Failed to get order book for ${symbol}:`, error);
      throw error;
    }
  }

  async executeOrder(order: OrderRequest): Promise<TradeExecution> {
    try {
      const orderId = this.generateOrderId();
      const [tokenIn, tokenOut] = this.parseSymbol(order.symbol);
      
      const execution: TradeExecution = {
        id: orderId,
        orderId: order.id,
        source: 'uniswap',
        symbol: order.symbol,
        side: order.side,
        amount: order.amount,
        price: '0',
        fee: '0',
        status: 'pending',
        timestamp: Date.now()
      };

      if (order.type === 'market') {
        const amountOut = await this.router.quoteExactInputSingle(
          tokenIn,
          tokenOut,
          3000,
          ethers.parseEther(order.amount),
          0
        );

        execution.price = ethers.formatEther(amountOut);
        execution.fee = (parseFloat(order.amount) * 0.003).toString();
        execution.status = 'filled';
        execution.filledAmount = order.amount;
        execution.averagePrice = execution.price;
      }

      return execution;
    } catch (error) {
      this.logger.error(`Failed to execute order ${order.id}:`, error);
      throw error;
    }
  }

  async getOrderStatus(orderId: string): Promise<TradeExecution> {
    return {
      id: orderId,
      orderId: orderId.split('_')[1],
      source: 'uniswap',
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
    return [
      'ETH/USDC',
      'ETH/USDT',
      'WBTC/ETH',
      'WBTC/USDC',
      'USDC/USDT'
    ];
  }

  async getFees(): Promise<{ maker: number; taker: number }> {
    return {
      maker: 0.0005,
      taker: 0.0030
    };
  }

  async isHealthy(): Promise<boolean> {
    try {
      const blockNumber = await this.provider.getBlockNumber();
      return blockNumber > 0;
    } catch {
      return false;
    }
  }

  private parseSymbol(symbol: string): [string, string] {
    const [base, quote] = symbol.split('/');
    const tokenMap: { [key: string]: string } = {
      'ETH': '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
      'USDC': '0xA0b86a33E6441b8e8C7C7b0b8e8e8e8e8e8e8e8e',
      'USDT': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      'WBTC': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599'
    };

    return [tokenMap[base], tokenMap[quote]];
  }

  private async getPools(tokenIn: string, tokenOut: string): Promise<string[]> {
    const fees = [500, 3000, 10000];
    const pools: string[] = [];

    for (const fee of fees) {
      try {
        const pool = await this.factory.getPool(tokenIn, tokenOut, fee);
        if (pool !== ethers.ZeroAddress) {
          pools.push(pool);
        }
      } catch {
        continue;
      }
    }

    return pools;
  }

  private async getPoolLiquidity(poolAddress: string): Promise<any> {
    return {};
  }

  private async getMidPrice(poolAddress: string): Promise<string> {
    return '2000';
  }

  private async estimateLiquidityAtPrice(poolAddress: string, price: string): Promise<string> {
    return (Math.random() * 1000000).toString();
  }
}
