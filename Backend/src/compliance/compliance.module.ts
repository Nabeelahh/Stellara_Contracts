import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './services/compliance.service';
import { SanctionsScreeningService } from './services/sanctions-screening.service';
import { TravelRuleService } from './services/travel-rule.service';
import { CurrencyControlService } from './services/currency-control.service';

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
  ],
  controllers: [ComplianceController],
  providers: [
    ComplianceService,
    SanctionsScreeningService,
    TravelRuleService,
    CurrencyControlService,
  ],
  exports: [
    ComplianceService,
    SanctionsScreeningService,
    TravelRuleService,
    CurrencyControlService,
  ],
})
export class ComplianceModule {}
