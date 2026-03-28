import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Param, 
  Query,
  Delete,
  HttpCode,
  HttpStatus
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { 
  OrderRequest, 
  ExecutionPlan, 
  TradeExecution, 
  AggregatedOrderBook, 
  ArbitrageOpportunity,
  LiquiditySource,
  PerformanceMetrics
} from '../interfaces/liquidity-aggregation.interface';
import { LiquidityAggregationService } from '../services/liquidity-aggregation.service';

@ApiTags('Liquidity Aggregation')
@Controller('liquidity-aggregation')
export class LiquidityAggregationController {
  constructor(private readonly liquidityAggregationService: LiquidityAggregationService) {}

  @Get('orderbook/:symbol')
  @ApiOperation({ summary: 'Get aggregated order book for a symbol' })
  @ApiParam({ name: 'symbol', description: 'Trading symbol (e.g., BTC/USDT)' })
  @ApiResponse({ status: 200, description: 'Aggregated order book retrieved successfully' })
  async getOrderBook(@Param('symbol') symbol: string): Promise<AggregatedOrderBook> {
    return this.liquidityAggregationService.getAggregatedOrderBook(symbol);
  }

  @Post('execution-plan')
  @ApiOperation({ summary: 'Create execution plan for an order' })
  @ApiResponse({ status: 200, description: 'Execution plan created successfully' })
  async createExecutionPlan(@Body() order: OrderRequest): Promise<ExecutionPlan> {
    return this.liquidityAggregationService.createExecutionPlan(order);
  }

  @Post('execute-order')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Execute a trade order' })
  @ApiResponse({ status: 200, description: 'Order executed successfully' })
  async executeOrder(@Body() order: OrderRequest): Promise<TradeExecution[]> {
    return this.liquidityAggregationService.executeOrder(order);
  }

  @Get('arbitrage-opportunities')
  @ApiOperation({ summary: 'Get arbitrage opportunities' })
  @ApiQuery({ name: 'symbol', required: false, description: 'Filter by symbol' })
  @ApiResponse({ status: 200, description: 'Arbitrage opportunities retrieved successfully' })
  async getArbitrageOpportunities(
    @Query('symbol') symbol?: string
  ): Promise<ArbitrageOpportunity[]> {
    return this.liquidityAggregationService.detectArbitrageOpportunities(symbol);
  }

  @Get('liquidity-sources')
  @ApiOperation({ summary: 'Get all liquidity sources' })
  @ApiResponse({ status: 200, description: 'Liquidity sources retrieved successfully' })
  async getLiquiditySources(): Promise<LiquiditySource[]> {
    return this.liquidityAggregationService.getLiquiditySources();
  }

  @Get('performance-metrics')
  @ApiOperation({ summary: 'Get performance metrics' })
  @ApiQuery({ name: 'source', required: false, description: 'Filter by source' })
  @ApiQuery({ name: 'symbol', required: false, description: 'Filter by symbol' })
  @ApiResponse({ status: 200, description: 'Performance metrics retrieved successfully' })
  async getPerformanceMetrics(
    @Query('source') source?: string,
    @Query('symbol') symbol?: string
  ): Promise<PerformanceMetrics[]> {
    return this.liquidityAggregationService.getPerformanceMetrics(source, symbol);
  }

  @Get('top-sources')
  @ApiOperation({ summary: 'Get top performing liquidity sources' })
  @ApiQuery({ name: 'limit', required: false, description: 'Number of sources to return', type: Number })
  @ApiResponse({ status: 200, description: 'Top performing sources retrieved successfully' })
  async getTopPerformingSources(@Query('limit') limit: number = 5): Promise<LiquiditySource[]> {
    return this.liquidityAggregationService.getTopPerformingSources(limit);
  }

  @Get('system-health')
  @ApiOperation({ summary: 'Get system health status' })
  @ApiResponse({ status: 200, description: 'System health retrieved successfully' })
  async getSystemHealth() {
    return this.liquidityAggregationService.getSystemHealth();
  }

  @Get('supported-symbols')
  @ApiOperation({ summary: 'Get all supported trading symbols' })
  @ApiResponse({ status: 200, description: 'Supported symbols retrieved successfully' })
  async getSupportedSymbols(): Promise<string[]> {
    return this.liquidityAggregationService.getSupportedSymbols();
  }

  @Post('refresh-orderbook/:symbol')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh order book for a symbol' })
  @ApiParam({ name: 'symbol', description: 'Trading symbol to refresh' })
  @ApiResponse({ status: 200, description: 'Order book refreshed successfully' })
  async refreshOrderBook(@Param('symbol') symbol: string): Promise<void> {
    return this.liquidityAggregationService.refreshOrderBook(symbol);
  }

  @Delete('cache')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Clear all caches' })
  @ApiResponse({ status: 200, description: 'Caches cleared successfully' })
  async clearAllCaches(): Promise<void> {
    return this.liquidityAggregationService.clearAllCaches();
  }
}
