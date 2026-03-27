import { ApiProperty } from '@nestjs/swagger';
import { IsISO8601, IsNumberString, IsString } from 'class-validator';

export class RenewCredentialDto {
  @ApiProperty({ description: 'Token id to renew' })
  @IsNumberString()
  tokenId: string;

  @ApiProperty({ description: 'New expiration ISO date' })
  @IsISO8601()
  newExpiresAt: string;

  @ApiProperty({ description: 'Contract address of the SBT' })
  @IsString()
  contractAddress: string;
}
