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
import { VestingService } from './vesting.service';
import {
  CreateVestingScheduleDto,
  TriggerAccelerationDto,
  TerminateVestingDto,
} from './vesting.dto';

@Controller('vesting')
export class VestingController {
  constructor(private readonly vestingService: VestingService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createSchedule(@Body() dto: CreateVestingScheduleDto) {
    return this.vestingService.createSchedule(dto);
  }

  @Get('tax-report/:address/:year')
  async generateTaxReport(
    @Param('address') address: string,
    @Param('year') year: string,
  ) {
    return this.vestingService.generateTaxReport(address, parseInt(year, 10));
  }

  @Get()
  async listSchedules(
    @Query('recipientAddress') recipientAddress?: string,
    @Query('status') status?: string,
  ) {
    return this.vestingService.listSchedules({ recipientAddress, status });
  }

  @Get(':id')
  async getSchedule(@Param('id') id: string) {
    return this.vestingService.getSchedule(id);
  }

  @Get(':id/vested')
  async calculateVested(
    @Param('id') id: string,
    @Query('asOfDate') asOfDate?: string,
  ) {
    const date = asOfDate ? new Date(asOfDate) : new Date();
    return this.vestingService.calculateVested(id, date);
  }

  @Post(':id/accelerate')
  @HttpCode(HttpStatus.OK)
  async triggerAcceleration(
    @Param('id') id: string,
    @Body() body: { reason: 'acquisition' | 'ipo' | 'termination' },
  ) {
    const dto: TriggerAccelerationDto = { vestingId: id, reason: body.reason };
    return this.vestingService.triggerAcceleration(dto);
  }

  @Post(':id/terminate')
  @HttpCode(HttpStatus.OK)
  async terminateVesting(
    @Param('id') id: string,
    @Body() body: { terminationDate: string; reason: string },
  ) {
    const dto: TerminateVestingDto = {
      vestingId: id,
      terminationDate: body.terminationDate,
      reason: body.reason,
    };
    return this.vestingService.terminateVesting(dto);
  }
}
