import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { IdentityService } from './identity.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { RevokeCredentialDto } from './dto/revoke-credential.dto';
import { RenewCredentialDto } from './dto/renew-credential.dto';

@ApiTags('identity')
@Controller('identity')
export class IdentityController {
  constructor(private readonly identity: IdentityService) {}

  @Post('issue')
  @ApiOperation({ summary: 'Issue verifiable credential and optionally mint SBT' })
  async issue(@Body() body: IssueCredentialDto) {
    return this.identity.issueCredential(body);
  }

  @Post('revoke')
  @ApiOperation({ summary: 'Revoke on-chain credential' })
  async revoke(@Body() body: RevokeCredentialDto) {
    const tokenId = Number(body.tokenId);
    return this.identity.revokeOnChain(body.contractAddress, tokenId);
  }

  @Post('renew')
  @ApiOperation({ summary: 'Renew on-chain credential expiration' })
  async renew(@Body() body: RenewCredentialDto) {
    const tokenId = Number(body.tokenId);
    const newExpiresAtUnix = Math.floor(new Date(body.newExpiresAt).getTime() / 1000);
    return this.identity.renewOnChain(body.contractAddress, tokenId, newExpiresAtUnix);
  }
}
