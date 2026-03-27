import { Module } from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { AnalyticsController } from './analytics.controller';
import { BehavioralAnalyticsService } from './behavioral-analytics.service';
import { BehavioralAnalyticsController } from './behavioral-analytics.controller';
import { PrismaService } from '../prisma.service';

@Module({
  controllers: [AnalyticsController, BehavioralAnalyticsController],
  providers: [AnalyticsService, BehavioralAnalyticsService, PrismaService],
  exports: [AnalyticsService, BehavioralAnalyticsService],
})
export class AnalyticsModule {}
