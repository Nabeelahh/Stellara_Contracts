import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

import { ExportRealtimeRollupsDto, QueryRealtimeRollupsDto } from './dto/realtime-analytics.dto';
import { RealtimeAnalyticsService } from './realtime-analytics.service';

@Controller('analytics/realtime')
export class RealtimeAnalyticsController {
  constructor(private readonly realtimeAnalyticsService: RealtimeAnalyticsService) {}

  @Get('live')
  getLiveMetrics() {
    return this.realtimeAnalyticsService.getLiveMetrics();
  }

  @Get('rollups')
  getRollups(@Query() query: QueryRealtimeRollupsDto) {
    return this.realtimeAnalyticsService.getRollups(query);
  }

  @Get('dashboard')
  getDashboard(@Query('from') from?: string, @Query('to') to?: string) {
    return this.realtimeAnalyticsService.getDashboardRange(from, to);
  }

  @Get('export')
  async exportRollups(
    @Query() query: ExportRealtimeRollupsDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const payload = await this.realtimeAnalyticsService.exportRollups({
      ...query,
      format: query.format || 'csv',
    });

    response.setHeader('Content-Type', payload.contentType);
    response.setHeader('Content-Disposition', `attachment; filename="${payload.filename}"`);
    return payload.content;
  }
}

