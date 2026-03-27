import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { MonitoringService } from './monitoring.service';

@Controller('monitoring')
export class MonitoringController {
  constructor(private readonly monitoringService: MonitoringService) {}

  @Get('status')
  async getStatusPage() {
    return this.monitoringService.getStatusPage();
  }

  @Get('latency/:testName')
  async getLatencyPercentiles(
    @Param('testName') testName: string,
    @Query('hours') hours?: string,
  ) {
    const hoursNum = hours ? parseFloat(hours) : 24;
    return this.monitoringService.getLatencyPercentiles(testName, hoursNum);
  }

  @Get('sla')
  async getSlaReport(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
  ) {
    const start = startDate ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const end = endDate ? new Date(endDate) : new Date();
    return this.monitoringService.getSlaReport(start, end);
  }

  @Get('trends/:testName')
  async getTrends(
    @Param('testName') testName: string,
    @Query('days') days?: string,
  ) {
    const daysNum = days ? parseInt(days, 10) : 7;
    return this.monitoringService.getTrends(testName, daysNum);
  }

  @Post('run')
  @HttpCode(HttpStatus.ACCEPTED)
  async runSyntheticTests() {
    // Fire and forget - runs asynchronously
    this.monitoringService.runSyntheticTests().catch((err) => {
      // Errors are logged internally by the service
    });
    return { message: 'Synthetic test run triggered', timestamp: new Date() };
  }
}
