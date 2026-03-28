import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './services/compliance.service';
import { SanctionsScreeningService } from './services/sanctions-screening.service';
import { TravelRuleService } from './services/travel-rule.service';
import { CurrencyControlService } from './services/currency-control.service';
import { MarketSurveillanceService } from './services/market-surveillance.service';
import { PrismaModule } from '../prisma.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      'sanctions_list',
      'travel_rule_records',
      'compliance_audit_trail',
      'sar_reports',
      'ctr_reports',
      'currency_control_limits',
    ]),
    PrismaModule,
  ],
  controllers: [ComplianceController],
  providers: [
    ComplianceService,
    SanctionsScreeningService,
    TravelRuleService,
    CurrencyControlService,
    MarketSurveillanceService,
  ],
  exports: [
    ComplianceService,
    SanctionsScreeningService,
    TravelRuleService,
    CurrencyControlService,
    MarketSurveillanceService,
  ],
})
export class ComplianceModule {}
