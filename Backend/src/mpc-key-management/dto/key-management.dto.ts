import { IsString, IsNumber, IsEnum, IsOptional, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum KeyShareLocation {
  AWS_HSM = 'AWS_HSM',
  GCP_HSM = 'GCP_HSM',
  ON_PREM_HSM = 'ON_PREM_HSM',
  AZURE_KEY_VAULT = 'AZURE_KEY_VAULT',
}

export enum KeyStatus {
  ACTIVE = 'ACTIVE',
  ROTATING = 'ROTATING',
  COMPROMISED = 'COMPROMISED',
  REVOKED = 'REVOKED',
  PENDING_ACTIVATION = 'PENDING_ACTIVATION',
}

export enum ThresholdScheme {
  TWO_OF_THREE = '2-of-3',
  THREE_OF_FIVE = '3-of-5',
  FOUR_OF_SEVEN = '4-of-7',
}

export class GenerateKeyDto {
  @ApiProperty({ description: 'Threshold scheme (e.g., 2-of-3)' })
  @IsEnum(ThresholdScheme)
  thresholdScheme: ThresholdScheme;

  @ApiProperty({ description: 'Key purpose/identifier' })
  @IsString()
  keyPurpose: string;

  @ApiProperty({ description: 'Geographic distribution locations for shares' })
  @IsEnum(KeyShareLocation, { each: true })
  shareLocations: KeyShareLocation[];

  @ApiProperty({ description: 'Rotation period in days', required: false })
  @IsOptional()
  @IsNumber()
  rotationPeriodDays?: number;
}

export class SignTransactionDto {
  @ApiProperty({ description: 'Key ID to use for signing' })
  @IsString()
  keyId: string;

  @ApiProperty({ description: 'Transaction data to sign' })
  @IsString()
  transactionData: string;

  @ApiProperty({ description: 'Minimum shares required (overrides threshold if needed)' })
  @IsOptional()
  @IsNumber()
  minShares?: number;
}

export class RotateKeyDto {
  @ApiProperty({ description: 'Key ID to rotate' })
  @IsString()
  keyId: string;

  @ApiProperty({ description: 'Reason for rotation' })
  @IsString()
  reason: 'SCHEDULED' | 'COMPROMISE_DETECTED' | 'MANUAL' | 'SECURITY_POLICY';

  @ApiProperty({ description: 'New share locations (optional)' })
  @IsOptional()
  @IsEnum(KeyShareLocation, { each: true })
  newShareLocations?: KeyShareLocation[];
}

export class KeyCompromiseReportDto {
  @ApiProperty({ description: 'Key ID suspected of compromise' })
  @IsString()
  keyId: string;

  @ApiProperty({ description: 'Evidence of compromise' })
  @IsString()
  evidence: string;

  @ApiProperty({ description: 'Share location suspected' })
  @IsOptional()
  @IsEnum(KeyShareLocation)
  suspectedLocation?: KeyShareLocation;

  @ApiProperty({ description: 'Reporter ID' })
  @IsString()
  reportedBy: string;
}
