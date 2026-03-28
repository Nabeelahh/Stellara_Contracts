import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CommitRevealService } from './services/commit-reveal.service';
import { ThresholdEncryptionService } from './services/threshold-encryption.service';
import { IntelligentOrderRouter } from './services/intelligent-order-router.service';
import { CommitOrderDto, RevealOrderDto, ExecuteOrderDto } from '../dto/order.dto';

@ApiTags('MEV Protection')
@Controller('mev-protection')
export class MEVProtectionController {
  constructor(
    private readonly commitRevealService: CommitRevealService,
    private readonly thresholdEncryption: ThresholdEncryptionService,
    private readonly orderRouter: IntelligentOrderRouter,
  ) {}

  @Post('commit')
  @ApiOperation({ summary: 'Commit order hash (first phase of commit-reveal)' })
  @ApiResponse({ status: 201, description: 'Order committed successfully' })
  async commitOrder(@Body() dto: CommitOrderDto) {
    return this.commitRevealService.commitOrder(dto);
  }

  @Post('reveal')
  @ApiOperation({ summary: 'Reveal order details (second phase of commit-reveal)' })
  @ApiResponse({ status: 200, description: 'Order revealed and verified' })
  async revealOrder(@Body() dto: RevealOrderDto) {
    return this.commitRevealService.revealOrder(
      dto.commitmentId,
      dto.orderData,
      dto.nonce,
    );
  }

  @Post('encrypt-order')
  @ApiOperation({ summary: 'Encrypt order using threshold encryption' })
  @ApiResponse({ status: 201, description: 'Order encrypted with threshold scheme' })
  async encryptOrder(@Body() orderData: string) {
    return this.thresholdEncryption.encryptOrder(orderData);
  }

  @Post('collect-shares')
  @ApiOperation({ summary: 'Collect decryption shares from key holders' })
  @ApiResponse({ status: 200, description: 'Shares collected for decryption' })
  async collectShares(@Body() data: {
    orderId: string;
    shareholderResponses: Array<{ shareIndex: number; signature: string }>;
  }) {
    return this.thresholdEncryption.collectDecryptionShares(
      data.orderId,
      data.shareholderResponses,
    );
  }

  @Post('find-route')
  @ApiOperation({ summary: 'Find optimal multi-DEX route for best execution' })
  @ApiResponse({ status: 200, description: 'Optimal execution plan found' })
  async findOptimalRoute(@Body() params: {
    side: string;
    pair: string;
    amount: number;
    maxSlippageBps: number;
  }) {
    return this.orderRouter.findOptimalRoute(params);
  }

  @Post('execute')
  @ApiOperation({ summary: 'Execute order with MEV protection' })
  @ApiResponse({ status: 200, description: 'Order executed with MEV protection' })
  async executeOrder(@Body() dto: ExecuteOrderDto) {
    const executionPlan = await this.orderRouter.findOptimalRoute({
      side: 'BUY', // Would get from commitment
      pair: 'XLM/USDC',
      amount: 10000,
      maxSlippageBps: 50,
    });

    return this.orderRouter.executeWithMEVProtection({
      commitmentId: dto.commitmentId,
      executionPlan,
      useThresholdEncryption: true,
    });
  }

  @Get('commitment/:id')
  @ApiOperation({ summary: 'Get commitment details' })
  @ApiResponse({ status: 200, description: 'Commitment details retrieved' })
  async getCommitment(@Param('id') id: string) {
    return this.commitRevealService.getCommitment(id);
  }

  @Get('pending-commitments')
  @ApiOperation({ summary: 'Get all pending commitments awaiting execution' })
  @ApiResponse({ status: 200, description: 'List of pending commitments' })
  async getPendingCommitments() {
    return this.commitRevealService.getPendingCommitments();
  }

  @Get('commitment-stats')
  @ApiOperation({ summary: 'Get commitment statistics' })
  @ApiResponse({ status: 200, description: 'Commitment statistics' })
  async getCommitmentStats() {
    return this.commitRevealService.getCommitmentStats();
  }

  @Get('encryption-stats')
  @ApiOperation({ summary: 'Get threshold encryption statistics' })
  @ApiResponse({ status: 200, description: 'Encryption statistics' })
  async getEncryptionStats() {
    return this.thresholdEncryption.getEncryptionStats();
  }

  @Post('detect-sandwich')
  @ApiOperation({ summary: 'Detect potential sandwich attacks' })
  @ApiResponse({ status: 200, description: 'Sandwich attack detection result' })
  async detectSandwichAttack(@Body() data: {
    pendingOrders: Array<{ amount: number; side: string }>;
    timeWindowMs: number;
  }) {
    return this.orderRouter.detectSandwichAttack(data);
  }
}
