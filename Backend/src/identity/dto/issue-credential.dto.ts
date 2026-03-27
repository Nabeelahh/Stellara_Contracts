import { ApiProperty } from '@nestjs/swagger';
import { IsISO8601, IsObject, IsOptional, IsString } from 'class-validator';

export class IssueCredentialDto {
  @ApiProperty({ description: 'User id in platform' })
  @IsString()
  userId: string;

  @ApiProperty({ description: 'Recipient wallet address' })
  @IsString()
  recipientWallet: string;

  @ApiProperty({ description: 'Credential attributes (e.g., kyc: {age: 30})' })
  @IsObject()
  attributes: Record<string, any>;

  @ApiProperty({ description: 'Optional expiration ISO date', required: false })
  @IsOptional()
  @IsISO8601()
  expiresAt?: string;
}
