import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { AnalyticsService, PerformanceMetrics, BehavioralStats } from './analytics.service';
// import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard'; // Assuming JWT auth exists

@Controller('analytics')
// @UseGuards(JwtAuthGuard)
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get(':userId/performance')
  async getPerformance(@Param('userId') userId: string): Promise<PerformanceMetrics> {
    return await this.analyticsService.getPerformanceMetrics(userId);
  }

  @Get(':userId/behavior')
  async getBehavior(@Param('userId') userId: string): Promise<BehavioralStats> {
    return await this.analyticsService.getBehavioralAnalysis(userId);
  }

  @Get(':userId/patterns')
  async getPatterns(@Param('userId') userId: string): Promise<string[]> {
    return await this.analyticsService.detectPatterns(userId);
  }

  @Get(':userId/recommendations')
  async getRecommendations(@Param('userId') userId: string): Promise<string[]> {
    return await this.analyticsService.getRecommendations(userId);
  }

  @Get(':userId/summary')
  async getSummary(@Param('userId') userId: string) {
    const performance = await this.analyticsService.getPerformanceMetrics(userId);
    const behavior = await this.analyticsService.getBehavioralAnalysis(userId);
    const patterns = await this.analyticsService.detectPatterns(userId);
    const recommendations = await this.analyticsService.getRecommendations(userId);

    return {
      performance,
      behavior,
      patterns,
      recommendations,
    };
  }
}
