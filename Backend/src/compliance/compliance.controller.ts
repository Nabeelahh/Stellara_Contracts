import { Controller, Get, Post, Body, Param, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ComplianceService } from './services/compliance.service';
import { SanctionsScreeningService } from './services/sanctions-screening.service';
import { TravelRuleService } from './services/travel-rule.service';
import { CurrencyControlService } from './services/currency-control.service';
import {
  ScreenCounterpartyDto,
  TravelRuleDataDto,
  CurrencyControlCheckDto,
  ComplianceScoreDto,
} from './dto/compliance.dto';

@ApiTags('Compliance')
@Controller('compliance')
export class ComplianceController {
  constructor(
    private readonly complianceService: ComplianceService,
    private readonly sanctionsService: SanctionsScreeningService,
    private readonly travelRuleService: TravelRuleService,
    private readonly currencyControlService: CurrencyControlService,
  ) {}

  @Post('screen-counterparty')
  @ApiOperation({ summary: 'Screen counterparty against 15+ sanctions lists' })
  @ApiResponse({ status: 200, description: 'Sanctions screening result' })
  async screenCounterparty(@Body() dto: ScreenCounterpartyDto) {
    return this.sanctionsService.screenCounterparty(dto);
  }

  @Post('travel-rule')
  @ApiOperation({ summary: 'Collect Travel Rule data for transfers >$1,000' })
  @ApiResponse({ status: 200, description: 'Travel Rule compliance result' })
  async collectTravelRuleData(@Body() dto: TravelRuleDataDto) {
    return this.travelRuleService.collectTravelRuleData(dto);
  }

  @Post('currency-control')
  @ApiOperation({ summary: 'Verify currency exchange limits per jurisdiction' })
  @ApiResponse({ status: 200, description: 'Currency control verification result' })
  async verifyCurrencyControl(@Body() dto: CurrencyControlCheckDto) {
    return this.currencyControlService.verifyCurrencyControl(dto);
  }

  @Post('transaction-check')
  @ApiOperation({ summary: 'Perform comprehensive transaction compliance check' })
  @ApiResponse({ 
    status: 200, 
    description: 'Complete compliance check with scoring and recommendations',
  })
  async performTransactionCheck(@Body() params: {
    transactionId: string;
    originator: any;
    beneficiary: any;
    amount: any;
    userJurisdiction: string;
    paymentPurpose?: string;
  }) {
    return this.complianceService.performTransactionComplianceCheck(params);
  }

  @Post('generate-sar')
  @ApiOperation({ summary: 'Generate Suspicious Activity Report (SAR)' })
  @ApiResponse({ status: 201, description: 'SAR generated successfully' })
  async generateSAR(@Body() data: {
    transactionId: string;
    complianceResult: any;
    narrative: string;
    filedBy: string;
  }) {
    return this.complianceService.generateSuspiciousActivityReport(data);
  }

  @Post('generate-ctr')
  @ApiOperation({ summary: 'Generate Currency Transaction Report (CTR)' })
  @ApiResponse({ status: 201, description: 'CTR generated automatically' })
  async generateCTR(@Body() data: {
    transactionId: string;
    amount: number;
    originator: any;
    beneficiary: any;
    filedBy: string;
  }) {
    return this.complianceService.generateCurrencyTransactionReport(data);
  }

  @Get('audit-trail')
  @ApiOperation({ summary: 'Get compliance audit trail (7-year retention)' })
  @ApiResponse({ status: 200, description: 'Audit trail for regulatory examination' })
  async getAuditTrail(@Query() filters: {
    startDate: Date;
    endDate: Date;
    riskLevel?: string;
    transactionId?: string;
  }) {
    return this.complianceService.getAuditTrail(filters);
  }

  @Get('sanctions-stats')
  @ApiOperation({ summary: 'Get loaded sanctions lists statistics' })
  @ApiResponse({ status: 200, description: 'Statistics about sanctions lists' })
  async getSanctionsStats() {
    return this.sanctionsService.getSanctionsStats();
  }

  @Get('supported-jurisdictions')
  @ApiOperation({ summary: 'Get all supported jurisdictions with currency controls' })
  @ApiResponse({ status: 200, description: 'List of jurisdictions and their rules' })
  async getSupportedJurisdictions() {
    return this.currencyControlService.getSupportedJurisdictions();
  }

  @Get('travel-rule-report')
  @ApiOperation({ summary: 'Generate Travel Rule compliance report' })
  @ApiResponse({ status: 200, description: 'Travel Rule report for regulators' })
  async generateTravelRuleReport(@Query() period: { start: Date; end: Date }) {
    return this.travelRuleService.generateTravelRuleReport(period);
  }
}
