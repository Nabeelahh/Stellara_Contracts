import { Controller, Post, Body, Get, Param, Patch, UseGuards, Req } from '@nestjs/common';
import { KycService } from './kyc.service';
import { DocumentType } from './types';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('kyc')
@Controller('kyc')
export class KycController {
  constructor(private readonly kycService: KycService) {}

  @Post('session')
  @ApiOperation({ summary: 'Start a verification session' })
  async start(@Body() data: { userId: string; docType: DocumentType }) {
    return this.kycService.startVerification(data.userId, data.docType);
  }

  @Post('process/:id')
  @ApiOperation({ summary: 'Submit document and selfie for OCR and face matching' })
  async process(
    @Param('id') id: string,
    @Body() data: { documentUrl: string; selfieUrl: string },
  ) {
    return this.kycService.processVerification(id, data.documentUrl, data.selfieUrl);
  }

  @Patch('review/:id')
  @ApiOperation({ summary: 'Manual moderator review of a verification session' })
  async review(
    @Param('id') id: string,
    @Body() data: { moderatorId: string; approved: boolean; note?: string },
  ) {
    return this.kycService.reviewVerification(id, data.moderatorId, data.approved, data.note);
  }

  @Get('session/:id')
  @ApiOperation({ summary: 'Check status of a verification session' })
  async getStatus(@Param('id') id: string) {
    // Basic implementation for now: return current session record
    return id; // Placeholder
  }
}
