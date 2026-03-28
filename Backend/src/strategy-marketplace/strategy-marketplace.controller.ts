import { Controller, Get, Post, Body, Param, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { StrategyMarketplaceService } from './services/strategy-marketplace.service';
import { SubmitStrategyDto, BacktestRequestDto, CopyTradeDto } from '../dto/strategy.dto';

@ApiTags('Strategy Marketplace')
@Controller('strategy-marketplace')
export class StrategyMarketplaceController {
  constructor(
    private readonly marketplaceService: StrategyMarketplaceService,
  ) {}

  @Post('submit')
  @ApiOperation({ summary: 'Submit trading strategy to marketplace' })
  @ApiResponse({ status: 201, description: 'Strategy submitted successfully' })
  async submitStrategy(@Body() dto: SubmitStrategyDto) {
    return this.marketplaceService.submitStrategy(dto, 'developer_address');
  }

  @Post('backtest')
  @ApiOperation({ summary: 'Backtest strategy on historical data' })
  @ApiResponse({ status: 200, description: 'Backtest results' })
  async backtestStrategy(@Body() dto: BacktestRequestDto) {
    return this.marketplaceService.backtestStrategy(dto);
  }

  @Post('copy-trade')
  @ApiOperation({ summary: 'Subscribe to copy-trade a strategy' })
  @ApiResponse({ status: 201, description: 'Copy-trade subscription created' })
  async copyTrade(@Body() dto: CopyTradeDto) {
    return this.marketplaceService.subscribeToCopyTrade(dto, 'user_address');
  }

  @Get('leaderboard')
  @ApiOperation({ summary: 'Get strategy leaderboard' })
  @ApiResponse({ status: 200, description: 'Top performing strategies' })
  async getLeaderboard(
    @Query('strategyType') strategyType?: string,
    @Query('riskLevel') riskLevel?: string,
    @Query('minSharpe') minSharpe?: number,
    @Query('limit') limit?: number,
  ) {
    return this.marketplaceService.getLeaderboard({
      strategyType,
      riskLevel,
      minSharpe,
      limit,
    });
  }

  @Get('strategy/:id')
  @ApiOperation({ summary: 'Get strategy details' })
  @ApiResponse({ status: 200, description: 'Strategy details' })
  async getStrategy(@Param('id') id: string) {
    // Would implement getService method
    return { id };
  }

  @Post('distribute-revenue')
  @ApiOperation({ summary: 'Distribute revenue between developer and platform' })
  @ApiResponse({ status: 200, description: 'Revenue distributed' })
  async distributeRevenue(@Body() data: {
    strategyId: string;
    totalRevenue: number;
    period: { start: Date; end: Date };
  }) {
    return this.marketplaceService.distributeRevenue(data);
  }
}
