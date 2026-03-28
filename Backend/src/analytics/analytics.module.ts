import { Module } from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { AnalyticsController } from './analytics.controller';
import { BehavioralAnalyticsService } from './behavioral-analytics.service';
import { BehavioralAnalyticsController } from './behavioral-analytics.controller';
import { PrismaService } from '../prisma.service';
import { RealtimeAnalyticsController } from './realtime-analytics.controller';
import { RealtimeAnalyticsGateway } from './realtime-analytics.gateway';
import { RealtimeAnalyticsService } from './realtime-analytics.service';

@Module({
  controllers: [AnalyticsController, BehavioralAnalyticsController, RealtimeAnalyticsController],
  providers: [
    AnalyticsService,
    BehavioralAnalyticsService,
    RealtimeAnalyticsService,
    RealtimeAnalyticsGateway,
    PrismaService,
  ],
  exports: [AnalyticsService, BehavioralAnalyticsService, RealtimeAnalyticsService],
})
export class AnalyticsModule {}
