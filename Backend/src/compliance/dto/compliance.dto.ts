import { IsString, IsOptional, IsNumber, IsEnum, IsBoolean, IsDateString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum SanctionsListType {
  OFAC = 'OFAC',
  UN = 'UN',
  EU = 'EU',
  UK_HMT = 'UK_HMT',
  INTERPOL = 'INTERPOL',
  FINTRAC = 'FINTRAC',
  AUSTRAC = 'AUSTRAC',
  JAPAN_FSA = 'JAPAN_FSA',
  SINGAPORE_MAS = 'SINGAPORE_MAS',
  HK_MA = 'HK_MA',
  SWISS_FINMA = 'SWISS_FINMA',
  DUBAI_DFSA = 'DUBAI_DFSA',
  BAHRAIN_CBB = 'BAHRAIN_CBB',
  SOUTH_AFRICA_FSCA = 'SOUTH_AFRICA_FSCA',
  BRAZIL_BCB = 'BRAZIL_BCB',
  MEXICO_CNBV = 'MEXICO_CNBV',
}

export enum RiskLevel {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  MINIMAL = 'MINIMAL',
}

export class ScreenCounterpartyDto {
  @ApiProperty({ description: 'Full name of the counterparty' })
  @IsString()
  name: string;

  @ApiProperty({ description: 'Date of birth', required: false })
  @IsOptional()
  @IsDateString()
  dateOfBirth?: string;

  @ApiProperty({ description: 'Country of residence', required: false })
  @IsOptional()
  @IsString()
  country?: string;

  @ApiProperty({ description: 'Wallet address or account number', required: false })
  @IsOptional()
  @IsString()
  walletAddress?: string;

  @ApiProperty({ description: 'National ID or passport number', required: false })
  @IsOptional()
  @IsString()
  nationalId?: string;

  @ApiProperty({ description: 'Business registration number', required: false })
  @IsOptional()
  @IsString()
  registrationNumber?: string;
}

export class TravelRuleDataDto {
  @ApiProperty({ description: 'Originator full name' })
  @IsString()
  originatorName: string;

  @ApiProperty({ description: 'Originator wallet address' })
  @IsString()
  originatorAddress: string;

  @ApiProperty({ description: 'Originator account number', required: false })
  @IsOptional()
  @IsString()
  originatorAccountNumber?: string;

  @ApiProperty({ description: 'Beneficiary full name' })
  @IsString()
  beneficiaryName: string;

  @ApiProperty({ description: 'Beneficiary wallet address' })
  @IsString()
  beneficiaryAddress: string;

  @ApiProperty({ description: 'Beneficiary account number', required: false })
  @IsOptional()
  @IsString()
  beneficiaryAccountNumber?: string;

  @ApiProperty({ description: 'Transfer amount in USD cents' })
  @IsNumber()
  amountUsdCents: number;

  @ApiProperty({ description: 'Transaction hash', required: false })
  @IsOptional()
  @IsString()
  transactionHash?: string;
}

export class CurrencyControlCheckDto {
  @ApiProperty({ description: 'Source currency code' })
  @IsString()
  sourceCurrency: string;

  @ApiProperty({ description: 'Target currency code' })
  @IsString()
  targetCurrency: string;

  @ApiProperty({ description: 'Amount to exchange' })
  @IsNumber()
  amount: number;

  @ApiProperty({ description: 'User jurisdiction country code' })
  @IsString()
  userJurisdiction: string;

  @ApiProperty({ description: 'Purpose of payment', required: false })
  @IsOptional()
  @IsString()
  paymentPurpose?: string;
}

export class ComplianceScoreDto {
  @ApiProperty({ description: 'Overall compliance score (0-100)' })
  @IsNumber()
  score: number;

  @ApiProperty({ description: 'Risk level' })
  @IsEnum(RiskLevel)
  riskLevel: RiskLevel;

  @ApiProperty({ description: 'Sanctions check passed' })
  @IsBoolean()
  sanctionsPassed: boolean;

  @ApiProperty({ description: 'Travel rule compliance' })
  @IsBoolean()
  travelRuleCompliant: boolean;

  @ApiProperty({ description: 'Currency control check passed' })
  @IsBoolean()
  currencyControlPassed: boolean;

  @ApiProperty({ description: 'List of flags raised', isArray: true })
  flags: string[];

  @ApiProperty({ description: 'Recommended action' })
  @IsString()
  recommendedAction: 'APPROVE' | 'MANUAL_REVIEW' | 'REJECT' | 'BLOCK';
}
