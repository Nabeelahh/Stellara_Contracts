import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { BehavioralAnalyticsService, TrackEventDto } from './behavioral-analytics.service';

@Controller('analytics/behavioral')
export class BehavioralAnalyticsController {
  constructor(private readonly behavioralAnalyticsService: BehavioralAnalyticsService) {}

  @Post('track')
  @HttpCode(HttpStatus.CREATED)
  async trackEvent(@Body() dto: TrackEventDto) {
    return this.behavioralAnalyticsService.trackEvent(dto);
  }

  @Get('funnel/:funnelName')
  async getFunnelAnalysis(@Param('funnelName') funnelName: string) {
    return this.behavioralAnalyticsService.getFunnelAnalysis(funnelName);
  }

  @Get('cohort')
  async getCohortRetention(@Query('date') date: string) {
    const cohortDate = date ? new Date(date) : new Date();
    return this.behavioralAnalyticsService.getCohortRetention(cohortDate);
  }

  @Get('heatmap/:page')
  async getHeatmapData(@Param('page') page: string) {
    return this.behavioralAnalyticsService.getHeatmapData(decodeURIComponent(page));
  }

  @Post('opt-out/:userId')
  @HttpCode(HttpStatus.OK)
  async optOut(@Param('userId') userId: string) {
    return this.behavioralAnalyticsService.optOut(userId);
  }

  @Post('anonymize/:userId')
  @HttpCode(HttpStatus.OK)
  async anonymizeUser(@Param('userId') userId: string) {
    return this.behavioralAnalyticsService.anonymizeUser(userId);
  }
}
