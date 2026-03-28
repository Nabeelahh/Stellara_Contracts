import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SanctionsScreeningService } from './sanctions-screening.service';
import { TravelRuleService } from './travel-rule.service';
import { CurrencyControlService } from './currency-control.service';
import {
  ScreenCounterpartyDto,
  TravelRuleDataDto,
  CurrencyControlCheckDto,
  ComplianceScoreDto,
  RiskLevel,
} from '../dto/compliance.dto';

export interface TransactionComplianceResult {
  transactionId: string;
  overallScore: number;
  riskLevel: RiskLevel;
  sanctionsCheck: {
    passed: boolean;
    matches: any[];
    riskLevel: RiskLevel;
  };
  travelRuleCheck: {
    required: boolean;
    compliant: boolean;
    recordId?: string;
  };
  currencyControlCheck: {
    permitted: boolean;
    restrictions: string[];
  };
  ctrRequired: boolean;
  sarRecommended: boolean;
  flags: string[];
  recommendedAction: 'APPROVE' | 'MANUAL_REVIEW' | 'REJECT' | 'BLOCK';
  timestamp: Date;
}

@Injectable()
export class ComplianceService {
  private readonly logger = new Logger(ComplianceService.name);
  private readonly CTR_THRESHOLD_USD = 10000; // $10,000 for CTR filing
  private readonly SAR_THRESHOLD_SCORE = 30; // Below this, recommend SAR

  constructor(
    private readonly sanctionsService: SanctionsScreeningService,
    private readonly travelRuleService: TravelRuleService,
    private readonly currencyControlService: CurrencyControlService,
    @InjectRepository('compliance_audit_trail')
    private readonly auditRepo: Repository<any>,
    @InjectRepository('sar_reports')
    private readonly sarRepo: Repository<any>,
    @InjectRepository('ctr_reports')
    private readonly ctrRepo: Repository<any>,
  ) {}

  /**
   * Perform comprehensive compliance check on a transaction
   */
  async performTransactionComplianceCheck(params: {
    transactionId: string;
    originator: {
      name: string;
      walletAddress: string;
      country?: string;
      dateOfBirth?: string;
      nationalId?: string;
    };
    beneficiary: {
      name: string;
      walletAddress: string;
      country?: string;
    };
    amount: {
      value: number;
      currency: string;
      usdEquivalent: number;
    };
    userJurisdiction: string;
    paymentPurpose?: string;
  }): Promise<TransactionComplianceResult> {
    const flags: string[] = [];
    const timestamp = new Date();

    // 1. Sanctions screening for both parties
    this.logger.log(`Performing sanctions screening for transaction ${params.transactionId}`);
    
    const [originatorSanctionsCheck, beneficiarySanctionsCheck] = await Promise.all([
      this.sanctionsService.screenCounterparty({
        name: params.originator.name,
        walletAddress: params.originator.walletAddress,
        country: params.originator.country,
        dateOfBirth: params.originator.dateOfBirth,
        nationalId: params.originator.nationalId,
      }),
      this.sanctionsService.screenCounterparty({
        name: params.beneficiary.name,
        walletAddress: params.beneficiary.walletAddress,
        country: params.beneficiary.country,
      }),
    ]);

    const sanctionsPassed = 
      !originatorSanctionsCheck.isMatch && 
      !beneficiarySanctionsCheck.isMatch;

    if (originatorSanctionsCheck.isMatch) {
      flags.push(`Originator matched on ${originatorSanctionsCheck.riskLevel} risk sanctions list`);
    }
    if (beneficiarySanctionsCheck.isMatch) {
      flags.push(`Beneficiary matched on ${beneficiarySanctionsCheck.riskLevel} risk sanctions list`);
    }

    // 2. Travel Rule compliance check
    const requiresTravelRule = this.travelRuleService.requiresTravelRuleCompliance(
      params.amount.usdEquivalent * 100, // Convert to cents
    );

    let travelRuleCompliant = true;
    let travelRuleRecordId: string | undefined;

    if (requiresTravelRule) {
      try {
        const travelRuleResult = await this.travelRuleService.collectTravelRuleData({
          originatorName: params.originator.name,
          originatorAddress: params.originator.walletAddress,
          beneficiaryName: params.beneficiary.name,
          beneficiaryAddress: params.beneficiary.walletAddress,
          amountUsdCents: params.amount.usdEquivalent * 100,
          transactionHash: params.transactionId,
        });

        travelRuleCompliant = travelRuleResult.isCompliant;
        travelRuleRecordId = travelRuleResult.recordId;

        if (!travelRuleCompliant) {
          flags.push('Travel Rule compliance failed - missing required data');
        }
      } catch (error) {
        travelRuleCompliant = false;
        flags.push(`Travel Rule error: ${error.message}`);
      }
    }

    // 3. Currency control verification
    const currencyControlResult = await this.currencyControlService.verifyCurrencyControl({
      sourceCurrency: params.amount.currency,
      targetCurrency: 'USD', // Assuming conversion to USD
      amount: params.amount.usdEquivalent,
      userJurisdiction: params.userJurisdiction,
      paymentPurpose: params.paymentPurpose,
    });

    if (!currencyControlResult.isPermitted) {
      flags.push(...currencyControlResult.restrictions);
    }

    // 4. Determine if CTR (Currency Transaction Report) is required
    const ctrRequired = params.amount.usdEquivalent >= this.CTR_THRESHOLD_USD;
    if (ctrRequired) {
      flags.push('CTR filing required - transaction exceeds $10,000 threshold');
    }

    // 5. Calculate overall compliance score
    const overallScore = this.calculateComplianceScore({
      sanctionsOriginator: originatorSanctionsCheck,
      sanctionsBeneficiary: beneficiarySanctionsCheck,
      travelRuleCompliant,
      currencyControlPermitted: currencyControlResult.isPermitted,
      ctrRequired,
    });

    // 6. Determine risk level
    let riskLevel: RiskLevel = RiskLevel.MINIMAL;
    if (overallScore <= 20) {
      riskLevel = RiskLevel.CRITICAL;
    } else if (overallScore <= 40) {
      riskLevel = RiskLevel.HIGH;
    } else if (overallScore <= 60) {
      riskLevel = RiskLevel.MEDIUM;
    } else if (overallScore <= 80) {
      riskLevel = RiskLevel.LOW;
    } else {
      riskLevel = RiskLevel.MINIMAL;
    }

    // 7. Determine if SAR (Suspicious Activity Report) should be filed
    const sarRecommended = overallScore < this.SAR_THRESHOLD_SCORE || 
      originatorSanctionsCheck.riskLevel === RiskLevel.HIGH ||
      beneficiarySanctionsCheck.riskLevel === RiskLevel.HIGH;

    if (sarRecommended) {
      flags.push('SAR filing recommended due to suspicious activity patterns');
    }

    // 8. Determine recommended action
    let recommendedAction: 'APPROVE' | 'MANUAL_REVIEW' | 'REJECT' | 'BLOCK';
    
    if (originatorSanctionsCheck.riskLevel === RiskLevel.CRITICAL || 
        beneficiarySanctionsCheck.riskLevel === RiskLevel.CRITICAL) {
      recommendedAction = 'BLOCK';
    } else if (overallScore < 30 || !currencyControlResult.isPermitted) {
      recommendedAction = 'REJECT';
    } else if (overallScore < 60 || flags.length > 2) {
      recommendedAction = 'MANUAL_REVIEW';
    } else {
      recommendedAction = 'APPROVE';
    }

    // 9. Create audit trail entry (7-year retention)
    const auditEntry = await this.auditRepo.save({
      transactionId: params.transactionId,
      complianceScore: overallScore,
      riskLevel,
      sanctionsOriginator: originatorSanctionsCheck,
      sanctionsBeneficiary: beneficiarySanctionsCheck,
      travelRuleRequired: requiresTravelRule,
      travelRuleCompliant,
      travelRuleRecordId,
      currencyControlPermitted: currencyControlResult.isPermitted,
      ctrRequired,
      sarRecommended,
      flags,
      recommendedAction,
      auditDate: timestamp,
      retentionUntil: new Date(timestamp.setFullYear(timestamp.getFullYear() + 7)), // 7 years
    });

    this.logger.log(`Compliance check completed for ${params.transactionId}: ${recommendedAction}`);

    return {
      transactionId: params.transactionId,
      overallScore,
      riskLevel,
      sanctionsCheck: {
        passed: sanctionsPassed,
        matches: [...originatorSanctionsCheck.matches, ...beneficiarySanctionsCheck.matches],
        riskLevel: originatorSanctionsCheck.riskLevel === RiskLevel.CRITICAL || 
                   beneficiarySanctionsCheck.riskLevel === RiskLevel.CRITICAL
          ? RiskLevel.CRITICAL
          : originatorSanctionsCheck.riskLevel === RiskLevel.HIGH || 
            beneficiarySanctionsCheck.riskLevel === RiskLevel.HIGH
          ? RiskLevel.HIGH
          : RiskLevel.MEDIUM,
      },
      travelRuleCheck: {
        required: requiresTravelRule,
        compliant: travelRuleCompliant,
        recordId: travelRuleRecordId,
      },
      currencyControlCheck: {
        permitted: currencyControlResult.isPermitted,
        restrictions: currencyControlResult.restrictions,
      },
      ctrRequired,
      sarRecommended,
      flags,
      recommendedAction,
      timestamp,
    };
  }

  /**
   * Generate Suspicious Activity Report (SAR)
   */
  async generateSuspiciousActivityReport(data: {
    transactionId: string;
    complianceResult: TransactionComplianceResult;
    narrative: string;
    filedBy: string;
  }): Promise<string> {
    const sar = await this.sarRepo.save({
      transactionId: data.transactionId,
      filingDate: new Date(),
      status: 'PENDING_FILING',
      narrative: data.narrative,
      suspiciousIndicators: data.complianceResult.flags,
      riskLevel: data.complianceResult.riskLevel,
      amountInvolved: data.complianceResult.overallScore, // Placeholder
      filedBy: data.filedBy,
      regulatoryBody: 'FinCEN',
      metadata: data.complianceResult,
    });

    this.logger.log(`SAR generated: ${sar.id}`);
    return sar.id;
  }

  /**
   * Generate Currency Transaction Report (CTR)
   */
  async generateCurrencyTransactionReport(data: {
    transactionId: string;
    amount: number;
    originator: any;
    beneficiary: any;
    filedBy: string;
  }): Promise<string> {
    const ctr = await this.ctrRepo.save({
      transactionId: data.transactionId,
      filingDate: new Date(),
      status: 'PENDING_FILING',
      amount: data.amount,
      originatorInfo: data.originator,
      beneficiaryInfo: data.beneficiary,
      filedBy: data.filedBy,
      regulatoryBody: 'FinCEN',
    });

    this.logger.log(`CTR generated: ${ctr.id}`);
    return ctr.id;
  }

  /**
   * Get compliance audit trail for regulatory examination
   */
  async getAuditTrail(filters: {
    startDate: Date;
    endDate: Date;
    riskLevel?: RiskLevel;
    transactionId?: string;
  }): Promise<any[]> {
    const query = this.auditRepo.createQueryBuilder('audit');
    
    query.where('audit.auditDate BETWEEN :startDate AND :endDate', {
      startDate: filters.startDate,
      endDate: filters.endDate,
    });

    if (filters.riskLevel) {
      query.andWhere('audit.riskLevel = :riskLevel', { riskLevel: filters.riskLevel });
    }

    if (filters.transactionId) {
      query.andWhere('audit.transactionId = :transactionId', { 
        transactionId: filters.transactionId,
      });
    }

    return query.orderBy('audit.auditDate', 'DESC').getMany();
  }

  /**
   * Calculate compliance score (0-100, higher is better)
   */
  private calculateComplianceScore(params: {
    sanctionsOriginator: any;
    sanctionsBeneficiary: any;
    travelRuleCompliant: boolean;
    currencyControlPermitted: boolean;
    ctrRequired: boolean;
  }): number {
    let score = 100;

    // Sanctions matches are heavily penalized
    if (params.sanctionsOriginator.isMatch) {
      score -= params.sanctionsOriginator.riskLevel === RiskLevel.CRITICAL ? 80 :
               params.sanctionsOriginator.riskLevel === RiskLevel.HIGH ? 60 :
               params.sanctionsOriginator.riskLevel === RiskLevel.MEDIUM ? 40 : 20;
    }

    if (params.sanctionsBeneficiary.isMatch) {
      score -= params.sanctionsBeneficiary.riskLevel === RiskLevel.CRITICAL ? 80 :
               params.sanctionsBeneficiary.riskLevel === RiskLevel.HIGH ? 60 :
               params.sanctionsBeneficiary.riskLevel === RiskLevel.MEDIUM ? 40 : 20;
    }

    // Travel Rule non-compliance
    if (!params.travelRuleCompliant) {
      score -= 30;
    }

    // Currency control violation
    if (!params.currencyControlPermitted) {
      score -= 40;
    }

    // CTR requirement is neutral (just reporting)
    // But not filing when required would be penalized in real system

    return Math.max(0, Math.min(100, score));
  }
}
