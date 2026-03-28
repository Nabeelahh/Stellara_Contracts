// src/predictive-maintenance/predictive-maintenance.module.ts
import { Module } from '@nestjs/common';
import { PredictiveMaintenanceService } from './predictive-maintenance.service';
import { PredictiveMaintenanceController } from './predictive-maintenance.controller';

@Module({
  providers: [PredictiveMaintenanceService],
  controllers: [PredictiveMaintenanceController],
  exports: [PredictiveMaintenanceService],
})
export class PredictiveMaintenanceModule {}