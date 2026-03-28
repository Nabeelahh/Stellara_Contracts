import { Injectable, Logger } from '@nestjs/common';
import { CurrencyControlCheckDto } from '../dto/compliance.dto';

export interface CurrencyControlRule {
  id: string;
  jurisdiction: string;
  currencyPair: string; // e.g., "USD_EUR"
  dailyLimit?: number; // In USD equivalent
  monthlyLimit?: number; // In USD equivalent
  annualLimit?: number; // In USD equivalent
  requiresDocumentation: boolean;
  documentationThreshold: number; // Amount requiring docs
  permittedPurposes: string[];
  restrictedPurposes: string[];
  approvalRequired: boolean;
  metadata: Record<string, any>;
}

@Injectable()
export class CurrencyControlService {
  private readonly logger = new Logger(CurrencyControlService.name);
  
  // Comprehensive currency control rules by jurisdiction
  private readonly currencyRules: Map<string, CurrencyControlRule[]> = new Map();

  constructor() {
    this.initializeCurrencyRules();
  }

  /**
   * Initialize currency control rules for major jurisdictions
   */
  private initializeCurrencyRules(): void {
    const rules: CurrencyControlRule[] = [
      // China (CN) - Strict capital controls
      {
        id: 'cn_001',
        jurisdiction: 'CN',
        currencyPair: 'CNY_USD',
        dailyLimit: 50000, // $50k USD equivalent per day
        monthlyLimit: 200000,
        annualLimit: 500000,
        requiresDocumentation: true,
        documentationThreshold: 10000,
        permittedPurposes: ['trade', 'education', 'medical', 'travel'],
        restrictedPurposes: ['investment', 'real_estate', 'securities'],
        approvalRequired: true,
        metadata: { regulator: 'SAFE', country: 'China' },
      },
      
      // India (IN) - Liberalized Remittance Scheme
      {
        id: 'in_001',
        jurisdiction: 'IN',
        currencyPair: 'INR_USD',
        dailyLimit: 250000, // $250k USD per fiscal year
        monthlyLimit: 250000,
        annualLimit: 250000,
        requiresDocumentation: true,
        documentationThreshold: 25000,
        permittedPurposes: ['trade', 'education', 'medical', 'travel', 'gift'],
        restrictedPurposes: ['gambling', 'lottery'],
        approvalRequired: false,
        metadata: { regulator: 'RBI', country: 'India', scheme: 'LRS' },
      },
      
      // South Korea (KR)
      {
        id: 'kr_001',
        jurisdiction: 'KR',
        currencyPair: 'KRW_USD',
        dailyLimit: 50000,
        monthlyLimit: 150000,
        annualLimit: 500000,
        requiresDocumentation: true,
        documentationThreshold: 50000,
        permittedPurposes: ['trade', 'education', 'medical', 'travel', 'investment'],
        restrictedPurposes: [],
        approvalRequired: false,
        metadata: { regulator: 'FSS', country: 'South Korea' },
      },
      
      // Brazil (BR)
      {
        id: 'br_001',
        jurisdiction: 'BR',
        currencyPair: 'BRL_USD',
        dailyLimit: 100000,
        monthlyLimit: 300000,
        annualLimit: 1000000,
        requiresDocumentation: true,
        documentationThreshold: 10000,
        permittedPurposes: ['trade', 'investment', 'education', 'medical'],
        restrictedPurposes: ['gambling'],
        approvalRequired: false,
        metadata: { regulator: 'BCB', country: 'Brazil' },
      },
      
      // Russia (RU) - Capital controls
      {
        id: 'ru_001',
        jurisdiction: 'RU',
        currencyPair: 'RUB_USD',
        dailyLimit: 10000,
        monthlyLimit: 50000,
        annualLimit: 150000,
        requiresDocumentation: true,
        documentationThreshold: 5000,
        permittedPurposes: ['trade', 'medical', 'family_support'],
        restrictedPurposes: ['investment_abroad', 'real_estate_abroad'],
        approvalRequired: true,
        metadata: { regulator: 'CBR', country: 'Russia' },
      },
      
      // Nigeria (NG)
      {
        id: 'ng_001',
        jurisdiction: 'NG',
        currencyPair: 'NGN_USD',
        dailyLimit: 10000,
        monthlyLimit: 50000,
        annualLimit: 200000,
        requiresDocumentation: true,
        documentationThreshold: 2000,
        permittedPurposes: ['trade', 'education', 'medical'],
        restrictedPurposes: ['gambling', 'crypto'],
        approvalRequired: true,
        metadata: { regulator: 'CBN', country: 'Nigeria' },
      },
      
      // Saudi Arabia (SA)
      {
        id: 'sa_001',
        jurisdiction: 'SA',
        currencyPair: 'SAR_USD',
        dailyLimit: 170000, // SAR 637,500
        monthlyLimit: 500000,
        annualLimit: 2000000,
        requiresDocumentation: false,
        documentationThreshold: 100000,
        permittedPurposes: ['all'],
        restrictedPurposes: ['gambling'],
        approvalRequired: false,
        metadata: { regulator: 'SAMA', country: 'Saudi Arabia' },
      },
      
      // UAE (AE) - Relatively open
      {
        id: 'ae_001',
        jurisdiction: 'AE',
        currencyPair: 'AED_USD',
        dailyLimit: 500000,
        monthlyLimit: 1500000,
        annualLimit: 5000000,
        requiresDocumentation: false,
        documentationThreshold: 50000,
        permittedPurposes: ['all'],
        restrictedPurposes: [],
        approvalRequired: false,
        metadata: { regulator: 'CBUAE', country: 'UAE' },
      },
      
      // Singapore (SG) - Open with AML checks
      {
        id: 'sg_001',
        jurisdiction: 'SG',
        currencyPair: 'SGD_USD',
        dailyLimit: 1000000,
        monthlyLimit: 3000000,
        annualLimit: 10000000,
        requiresDocumentation: false,
        documentationThreshold: 20000,
        permittedPurposes: ['all'],
        restrictedPurposes: [],
        approvalRequired: false,
        metadata: { regulator: 'MAS', country: 'Singapore' },
      },
      
      // USA - Generally open, but reporting requirements
      {
        id: 'us_001',
        jurisdiction: 'US',
        currencyPair: 'USD_ALL',
        dailyLimit: undefined, // No hard limit
        monthlyLimit: undefined,
        annualLimit: undefined,
        requiresDocumentation: false,
        documentationThreshold: 10000, // CTR filing threshold
        permittedPurposes: ['all'],
        restrictedPurposes: ['sanctioned_countries'],
        approvalRequired: false,
        metadata: { 
          regulator: 'FinCEN', 
          country: 'USA',
          reportingRequirements: ['CTR', 'FBAR', 'FATCA'],
        },
      },
    ];

    // Group rules by jurisdiction
    rules.forEach((rule) => {
      const existing = this.currencyRules.get(rule.jurisdiction) || [];
      existing.push(rule);
      this.currencyRules.set(rule.jurisdiction, existing);
    });

    this.logger.log(`Initialized currency control rules for ${this.currencyRules.size} jurisdictions`);
  }

  /**
   * Verify currency exchange against jurisdiction limits
   */
  async verifyCurrencyControl(data: CurrencyControlCheckDto): Promise<{
    isPermitted: boolean;
    remainingLimits: {
      daily?: number;
      monthly?: number;
      annual?: number;
    };
    requiresDocumentation: boolean;
    requiresApproval: boolean;
    restrictions: string[];
    warnings: string[];
  }> {
    const restrictions: string[] = [];
    const warnings: string[] = [];
    const remainingLimits: { daily?: number; monthly?: number; annual?: number } = {};

    // Get rules for jurisdiction
    const rules = this.currencyRules.get(data.userJurisdiction) || [];
    
    if (rules.length === 0) {
      warnings.push(`No currency control rules found for jurisdiction: ${data.userJurisdiction}`);
      return {
        isPermitted: true,
        remainingLimits: {},
        requiresDocumentation: false,
        requiresApproval: false,
        restrictions: [],
        warnings,
      };
    }

    // Find applicable rule for currency pair
    const applicableRule = rules.find(
      (rule) => 
        rule.currencyPair === `${data.sourceCurrency}_${data.targetCurrency}` ||
        rule.currencyPair === `${data.sourceCurrency}_ALL`,
    );

    if (!applicableRule) {
      warnings.push(`No specific rules for currency pair: ${data.sourceCurrency}_${data.targetCurrency}`);
      return {
        isPermitted: true,
        remainingLimits: {},
        requiresDocumentation: false,
        requiresApproval: false,
        restrictions: [],
        warnings,
      };
    }

    // Check payment purpose restrictions
    if (data.paymentPurpose) {
      const normalizedPurpose = data.paymentPurpose.toLowerCase();
      
      if (applicableRule.restrictedPurposes.includes(normalizedPurpose)) {
        restrictions.push(`Purpose '${data.paymentPurpose}' is restricted for ${data.userJurisdiction}`);
      }
      
      if (
        applicableRule.permittedPurposes.length > 0 &&
        !applicableRule.permittedPurposes.includes('all') &&
        !applicableRule.permittedPurposes.includes(normalizedPurpose)
      ) {
        warnings.push(`Purpose '${data.paymentPurpose}' may require additional documentation`);
      }
    }

    // Check limits (retrieve user's historical transactions from DB in production)
    // For now, we'll just check if amount exceeds thresholds
    const amountUsd = data.amount; // Assume already converted to USD

    if (applicableRule.dailyLimit && amountUsd > applicableRule.dailyLimit) {
      restrictions.push(
        `Amount exceeds daily limit of $${applicableRule.dailyLimit.toLocaleString()} for ${data.userJurisdiction}`,
      );
      remainingLimits.daily = 0;
    } else if (applicableRule.dailyLimit) {
      remainingLimits.daily = applicableRule.dailyLimit - amountUsd;
    }

    if (applicableRule.monthlyLimit && amountUsd > applicableRule.monthlyLimit) {
      restrictions.push(
        `Amount exceeds monthly limit of $${applicableRule.monthlyLimit.toLocaleString()} for ${data.userJurisdiction}`,
      );
      remainingLimits.monthly = 0;
    } else if (applicableRule.monthlyLimit) {
      remainingLimits.monthly = applicableRule.monthlyLimit - amountUsd;
    }

    if (applicableRule.annualLimit && amountUsd > applicableRule.annualLimit) {
      restrictions.push(
        `Amount exceeds annual limit of $${applicableRule.annualLimit.toLocaleString()} for ${data.userJurisdiction}`,
      );
      remainingLimits.annual = 0;
    } else if (applicableRule.annualLimit) {
      remainingLimits.annual = applicableRule.annualLimit - amountUsd;
    }

    // Check documentation requirements
    const requiresDocumentation = 
      applicableRule.requiresDocumentation &&
      amountUsd >= applicableRule.documentationThreshold;

    return {
      isPermitted: restrictions.length === 0,
      remainingLimits,
      requiresDocumentation,
      requiresApproval: applicableRule.approvalRequired,
      restrictions,
      warnings,
    };
  }

  /**
   * Get all supported jurisdictions and their currency control summary
   */
  getSupportedJurisdictions(): Array<{
    jurisdiction: string;
    countryName: string;
    currencyPairs: string[];
    hasRestrictions: boolean;
  }> {
    const result: Array<{
      jurisdiction: string;
      countryName: string;
      currencyPairs: string[];
      hasRestrictions: boolean;
    }> = [];

    this.currencyRules.forEach((rules, jurisdiction) => {
      const countryName = rules[0]?.metadata?.country || 'Unknown';
      const currencyPairs = [...new Set(rules.map(r => r.currencyPair))];
      const hasRestrictions = rules.some(r => r.restrictedPurposes.length > 0 || r.approvalRequired);

      result.push({
        jurisdiction,
        countryName,
        currencyPairs,
        hasRestrictions,
      });
    });

    return result.sort((a, b) => a.countryName.localeCompare(b.countryName));
  }
}
