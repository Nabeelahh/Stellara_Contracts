import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { MPCKeysService } from './services/mpc-keys.service';
import { HSMIntegrationService } from './services/hsm-integration.service';
import {
  GenerateKeyDto,
  SignTransactionDto,
  RotateKeyDto,
  KeyCompromiseReportDto,
} from '../dto/key-management.dto';

@ApiTags('MPC Key Management')
@Controller('mpc-keys')
export class MPCKeysController {
  constructor(
    private readonly mpcKeysService: MPCKeysService,
    private readonly hsmService: HSMIntegrationService,
  ) {}

  @Post('generate')
  @ApiOperation({ summary: 'Generate distributed MPC key using threshold scheme' })
  @ApiResponse({ status: 201, description: 'MPC key generated successfully' })
  async generateKey(@Body() dto: GenerateKeyDto) {
    return this.mpcKeysService.generateDistributedKey(dto);
  }

  @Post('sign')
  @ApiOperation({ summary: 'Sign transaction using threshold signatures' })
  @ApiResponse({ status: 200, description: 'Transaction signed successfully' })
  async signTransaction(@Body() dto: SignTransactionDto) {
    return this.mpcKeysService.signWithThreshold(dto);
  }

  @Post('rotate')
  @ApiOperation({ summary: 'Rotate key shares proactively' })
  @ApiResponse({ status: 200, description: 'Key rotated successfully' })
  async rotateKey(@Body() dto: RotateKeyDto) {
    return this.mpcKeysService.rotateKeyShares(dto);
  }

  @Post('report-compromise')
  @ApiOperation({ summary: 'Report potential key compromise' })
  @ApiResponse({ status: 200, description: 'Compromise report processed' })
  async reportCompromise(@Body() dto: KeyCompromiseReportDto) {
    return this.mpcKeysService.detectCompromise(dto);
  }

  @Get('key/:id')
  @ApiOperation({ summary: 'Get key details' })
  @ApiResponse({ status: 200, description: 'Key details retrieved' })
  async getKey(@Param('id') id: string) {
    return this.mpcKeysService.getKey(id);
  }

  @Get('active')
  @ApiOperation({ summary: 'Get all active keys' })
  @ApiResponse({ status: 200, description: 'Active keys listed' })
  async getActiveKeys() {
    return this.mpcKeysService.getActiveKeys();
  }

  @Get('rotation-needed')
  @ApiOperation({ summary: 'Get keys needing rotation soon' })
  @ApiResponse({ status: 200, description: 'Keys scheduled for rotation' })
  async getKeysNeedingRotation(@Param('days') days: number = 7) {
    return this.mpcKeysService.getKeysNeedingRotation(days);
  }

  @Post('hsm/backup')
  @ApiOperation({ summary: 'Backup HSM keys to secondary location' })
  @ApiResponse({ status: 200, description: 'Backup completed' })
  async backupKeys(@Body() data: {
    sourceLocation: string;
    backupLocation: string;
  }) {
    return this.hsmService.backupKeys(data);
  }

  @Get('hsm/health/:location')
  @ApiOperation({ summary: 'Check HSM health status' })
  @ApiResponse({ status: 200, description: 'HSM health status' })
  async checkHSMHealth(@Param('location') location: string) {
    return this.hsmService.verifyHSMHealth(location as any);
  }
}
