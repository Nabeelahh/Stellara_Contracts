import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';

import { DataRetentionService } from './data-retention.service';
import {
  CreateLegalHoldDto,
  CreateRetentionRuleDto,
  ExecuteRetentionDto,
  ForgetUserDto,
  UpdateRetentionRuleDto,
} from './dto/data-retention.dto';

@Controller('data-retention')
export class DataRetentionController {
  constructor(private readonly dataRetentionService: DataRetentionService) {}

  @Post('rules')
  createRule(@Body() dto: CreateRetentionRuleDto) {
    return this.dataRetentionService.createRule(dto);
  }

  @Get('rules')
  listRules(@Query('tenantId') tenantId?: string) {
    return this.dataRetentionService.listRules(tenantId);
  }

  @Get('rules/:id')
  getRule(@Param('id') ruleId: string) {
    return this.dataRetentionService.getRule(ruleId);
  }

  @Patch('rules/:id')
  updateRule(@Param('id') ruleId: string, @Body() dto: UpdateRetentionRuleDto) {
    return this.dataRetentionService.updateRule(ruleId, dto);
  }

  @Post('rules/:id/execute')
  executeRule(@Param('id') ruleId: string, @Body() dto: ExecuteRetentionDto) {
    return this.dataRetentionService.executeRule(ruleId, dto.dryRun ?? false);
  }

  @Get('executions')
  listExecutions(@Query('limit') limit = '50') {
    const parsedLimit = Number.parseInt(limit, 10);
    return this.dataRetentionService.getExecutions(Number.isNaN(parsedLimit) ? 50 : parsedLimit);
  }

  @Post('legal-holds')
  createLegalHold(@Body() dto: CreateLegalHoldDto) {
    return this.dataRetentionService.createLegalHold(dto);
  }

  @Get('legal-holds')
  listLegalHolds(@Query('activeOnly') activeOnly = 'true') {
    return this.dataRetentionService.listLegalHolds(this.parseBoolean(activeOnly, true));
  }

  @Post('legal-holds/:id/release')
  releaseLegalHold(@Param('id') holdId: string, @Query('releasedBy') releasedBy?: string) {
    return this.dataRetentionService.releaseLegalHold(holdId, releasedBy);
  }

  @Post('forget/:userId')
  forgetUser(@Param('userId') userId: string, @Body() dto: ForgetUserDto) {
    return this.dataRetentionService.forgetUser(userId, dto);
  }

  @Get('report')
  complianceReport(@Query('days') days = '30') {
    const parsedDays = Number.parseInt(days, 10);
    return this.dataRetentionService.getComplianceReport(Number.isNaN(parsedDays) ? 30 : parsedDays);
  }

  private parseBoolean(value: string | undefined, fallback: boolean): boolean {
    if (value === undefined || value === null) {
      return fallback;
    }

    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) {
      return true;
    }
    if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) {
      return false;
    }
    return fallback;
  }
}
