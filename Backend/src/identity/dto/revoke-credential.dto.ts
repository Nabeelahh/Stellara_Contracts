import { ApiProperty } from '@nestjs/swagger';
import { IsNumberString, IsString } from 'class-validator';

export class RevokeCredentialDto {
  @ApiProperty({ description: 'Token id to revoke' })
  @IsNumberString()
  tokenId: string;

  @ApiProperty({ description: 'Contract address of the SBT' })
  @IsString()
  contractAddress: string;
}
