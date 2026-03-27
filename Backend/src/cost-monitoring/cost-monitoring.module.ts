// src/cost-monitoring/cost-monitoring.module.ts
import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ScheduleModule } from '@nestjs/schedule';
import { CostMonitoringService } from './cost-monitoring.service';

@Module({
  imports: [HttpModule, ScheduleModule.forRoot()],
  providers: [CostMonitoringService],
  exports: [CostMonitoringService],
})
export class CostMonitoringModule {}