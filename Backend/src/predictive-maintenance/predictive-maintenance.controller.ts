// src/predictive-maintenance/predictive-maintenance.controller.ts
import { Controller, Get, Post, Query, Body } from '@nestjs/common';
import { PredictiveMaintenanceService } from './predictive-maintenance.service';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Predictive Maintenance')
@Controller('predictive-maintenance')
export class PredictiveMaintenanceController {
  constructor(
    private readonly predictiveMaintenanceService: PredictiveMaintenanceService,
  ) {}

  @Get('health')
  @ApiOperation({ summary: 'Get system health status' })
  @ApiResponse({ status: 200, description: 'System health information' })
  async getSystemHealth() {
    return this.predictiveMaintenanceService.getSystemHealth();
  }

  @Get('metrics')
  @ApiOperation({ summary: 'Get current system metrics' })
  @ApiResponse({ status: 200, description: 'Current system metrics' })
  async getCurrentMetrics() {
    return this.predictiveMaintenanceService.getCurrentMetrics();
  }

  @Get('predictions')
  @ApiOperation({ summary: 'Get active predictions' })
  @ApiResponse({ status: 200, description: 'Active predictions' })
  async getActivePredictions(@Query('type') type?: string) {
    return this.predictiveMaintenanceService.getActivePredictions(type);
  }

  @Get('anomalies')
  @ApiOperation({ summary: 'Get detected anomalies' })
  @ApiResponse({ status: 200, description: 'Detected anomalies' })
  async getDetectedAnomalies(@Query('hours') hours: number = 24) {
    return this.predictiveMaintenanceService.getDetectedAnomalies(hours);
  }

  @Get('maintenance-tickets')
  @ApiOperation({ summary: 'Get maintenance tickets' })
  @ApiResponse({ status: 200, description: 'Maintenance tickets' })
  async getMaintenanceTickets(@Query('status') status?: string) {
    return this.predictiveMaintenanceService.getMaintenanceTickets(status);
  }

  @Post('analyze')
  @ApiOperation({ summary: 'Trigger manual analysis' })
  @ApiResponse({ status: 200, description: 'Analysis results' })
  async triggerAnalysis(@Body() options?: { force?: boolean }) {
    return this.predictiveMaintenanceService.performFullAnalysis(options?.force);
  }

  @Get('forecast')
  @ApiOperation({ summary: 'Get capacity forecasts' })
  @ApiResponse({ status: 200, description: 'Capacity forecasts' })
  async getCapacityForecasts(@Query('days') days: number = 7) {
    return this.predictiveMaintenanceService.getCapacityForecasts(days);
  }

  @Get('model-performance')
  @ApiOperation({ summary: 'Get ML model performance metrics' })
  @ApiResponse({ status: 200, description: 'Model performance metrics' })
  async getModelPerformance() {
    return this.predictiveMaintenanceService.getModelPerformance();
  }
}