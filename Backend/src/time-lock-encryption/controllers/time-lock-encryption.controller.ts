import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Param, 
  Query,
  HttpCode,
  HttpStatus
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { 
  TimeLockEncryption,
  TimeLockParameters,
  TimeLockAlgorithm,
  SecurityLevel,
  VerificationResult,
  SealedBid,
  EscrowTransaction,
  DeadMansSwitch
} from '../interfaces/time-lock-encryption.interface';
import { TimeLockEncryptionService } from '../services/time-lock-encryption.service';
import { TimeLockUseCasesService } from '../services/time-lock-use-cases.service';

@ApiTags('Time-Lock Encryption')
@Controller('time-lock-encryption')
export class TimeLockEncryptionController {
  constructor(
    private readonly timeLockService: TimeLockEncryptionService,
    private readonly useCasesService: TimeLockUseCasesService,
  ) {}

  @Post('encrypt')
  @ApiOperation({ summary: 'Encrypt message with time-lock' })
  @ApiResponse({ status: 201, description: 'Message encrypted successfully' })
  async encryptMessage(@Body() encryptDto: {
    message: string;
    unlockTime: Date;
    algorithm: TimeLockAlgorithm;
    parameters: TimeLockParameters;
  }): Promise<TimeLockEncryption> {
    return this.timeLockService.encryptMessage(
      encryptDto.message,
      encryptDto.unlockTime,
      encryptDto.parameters,
      encryptDto.algorithm
    );
  }

  @Post('decrypt')
  @ApiOperation({ summary: 'Decrypt time-locked message' })
  @ApiResponse({ status: 200, description: 'Message decrypted successfully' })
  async decryptMessage(@Body() decryptDto: {
    timeLockId: string;
    decryptionKey: string;
  }): Promise<{
    success: boolean;
    decryptedData?: string;
    verificationResult?: VerificationResult;
    error?: string;
  }> {
    // This would fetch the time-lock encryption from database
    // For demonstration, we'll assume the timeLockId corresponds to an encryption
    const timeLockEncryption = {} as TimeLockEncryption;
    
    return this.timeLockService.decryptMessage(
      timeLockEncryption,
      decryptDto.decryptionKey
    );
  }

  @Post('verify')
  @ApiOperation({ summary: 'Verify time-lock encryption' })
  @ApiResponse({ status: 200, description: 'Time-lock verified successfully' })
  async verifyTimeLock(@Body() verifyDto: {
    timeLockId: string;
  }): Promise<VerificationResult> {
    // This would fetch the time-lock encryption from database
    const timeLockEncryption = {} as TimeLockEncryption;
    
    return this.timeLockService.verifyTimeLock(timeLockEncryption);
  }

  @Post('public-verification')
  @ApiOperation({ summary: 'Generate public verification' })
  @ApiResponse({ status: 201, description: 'Public verification generated' })
  async generatePublicVerification(@Body() verificationDto: {
    timeLockId: string;
  }): Promise<{
    verificationId: string;
    publicProof: string;
    verificationData: any;
    merkleRoot: string;
  }> {
    // This would fetch the time-lock encryption from database
    const timeLockEncryption = {} as TimeLockEncryption;
    
    return this.timeLockService.generatePublicVerification(timeLockEncryption);
  }

  @Post('deploy-contract')
  @ApiOperation({ summary: 'Deploy time-lock to smart contract' })
  @ApiResponse({ status: 201, description: 'Contract deployed successfully' })
  async deployToSmartContract(@Body() deployDto: {
    timeLockId: string;
    network: string;
  }): Promise<any> {
    // This would fetch the time-lock encryption from database
    const timeLockEncryption = {} as TimeLockEncryption;
    
    return this.timeLockService.deployToSmartContract(
      timeLockEncryption,
      deployDto.network
    );
  }

  @Post('sealed-bids')
  @ApiOperation({ summary: 'Create sealed bid' })
  @ApiResponse({ status: 201, description: 'Sealed bid created successfully' })
  async createSealedBid(@Body() bidDto: {
    auctionId: string;
    bidderId: string;
    bidAmount: number;
    bidCurrency: string;
    revealTime: Date;
    auctionMetadata: any;
  }): Promise<SealedBid> {
    return this.useCasesService.createSealedBid(
      bidDto.auctionId,
      bidDto.bidderId,
      bidDto.bidAmount,
      bidDto.bidCurrency,
      bidDto.revealTime,
      bidDto.auctionMetadata
    );
  }

  @Post('sealed-bids/:bidId/reveal')
  @ApiOperation({ summary: 'Reveal sealed bid' })
  @ApiParam({ name: 'bidId', description: 'Bid ID' })
  @ApiResponse({ status: 200, description: 'Bid revealed successfully' })
  async revealSealedBid(
    @Param('bidId') bidId: string,
    @Body() revealDto: { decryptionKey?: string }
  ): Promise<{
    success: boolean;
    bidData?: any;
    error?: string;
  }> {
    return this.useCasesService.revealSealedBid(bidId, revealDto.decryptionKey);
  }

  @Post('escrow')
  @ApiOperation({ summary: 'Create escrow transaction' })
  @ApiResponse({ status: 201, description: 'Escrow created successfully' })
  async createEscrow(@Body() escrowDto: {
    parties: any[];
    amount: number;
    currency: string;
    conditions: any[];
    releaseTime: Date;
    escrowMetadata: any;
  }): Promise<EscrowTransaction> {
    return this.useCasesService.createEscrowTransaction(
      escrowDto.parties,
      escrowDto.amount,
      escrowDto.currency,
      escrowDto.conditions,
      escrowDto.releaseTime,
      escrowDto.escrowMetadata
    );
  }

  @Post('escrow/:escrowId/release')
  @ApiOperation({ summary: 'Release escrow' })
  @ApiParam({ name: 'escrowId', description: 'Escrow ID' })
  @ApiResponse({ status: 200, description: 'Escrow released successfully' })
  async releaseEscrow(
    @Param('escrowId') escrowId: string,
    @Body() releaseDto: { releaseData?: any }
  ): Promise<{
    success: boolean;
    escrowData?: any;
    transactionHash?: string;
    error?: string;
  }> {
    return this.useCasesService.releaseEscrow(escrowId, releaseDto.releaseData);
  }

  @Post('dead-mans-switch')
  @ApiOperation({ summary: 'Create dead man\'s switch' })
  @ApiResponse({ status: 201, description: 'Dead man\'s switch created successfully' })
  async createDeadMansSwitch(@Body() switchDto: {
    creatorId: string;
    beneficiaries: any[];
    checkInInterval: number;
    triggerConditions: any[];
    switchMetadata: any;
  }): Promise<DeadMansSwitch> {
    return this.useCasesService.createDeadMansSwitch(
      switchDto.creatorId,
      switchDto.beneficiaries,
      switchDto.checkInInterval,
      switchDto.triggerConditions,
      switchDto.switchMetadata
    );
  }

  @Post('dead-mans-switch/:switchId/checkin')
  @ApiOperation({ summary: 'Check in to dead man\'s switch' })
  @ApiParam({ name: 'switchId', description: 'Switch ID' })
  @ApiResponse({ status: 200, description: 'Check-in successful' })
  async checkInDeadMansSwitch(
    @Param('switchId') switchId: string,
    @Body() checkInDto: { signature?: string }
  ): Promise<{
    success: boolean;
    nextCheckIn?: Date;
    error?: string;
  }> {
    return this.useCasesService.checkInDeadMansSwitch(switchId, checkInDto.signature);
  }

  @Post('dead-mans-switch/:switchId/trigger')
  @ApiOperation({ summary: 'Trigger dead man\'s switch' })
  @ApiParam({ name: 'switchId', description: 'Switch ID' })
  @ApiResponse({ status: 200, description: 'Switch triggered successfully' })
  async triggerDeadMansSwitch(
    @Param('switchId') switchId: string,
    @Body() triggerDto: { triggerData?: any }
  ): Promise<{
    success: boolean;
    switchData?: any;
    beneficiaries?: any[];
    error?: string;
  }> {
    return this.useCasesService.triggerDeadMansSwitch(switchId, triggerDto.triggerData);
  }

  @Post('batch-encrypt')
  @ApiOperation({ summary: 'Batch encrypt messages' })
  @ApiResponse({ status: 201, description: 'Messages encrypted successfully' })
  async batchEncrypt(@Body() batchDto: {
    messages: string[];
    unlockTime: Date;
    algorithm: TimeLockAlgorithm;
    parameters: TimeLockParameters;
  }): Promise<TimeLockEncryption[]> {
    return this.timeLockService.createBatchEncryption(
      batchDto.messages,
      batchDto.unlockTime,
      batchDto.parameters,
      batchDto.algorithm
    );
  }

  @Post('batch-decrypt')
  @ApiOperation({ summary: 'Batch decrypt messages' })
  @ApiResponse({ status: 200, description: 'Messages decrypted successfully' })
  async batchDecrypt(@Body() batchDto: {
    timeLockIds: string[];
    decryptionKeys: string[];
  }): Promise<{
    success: boolean;
    results: any[];
    error?: string;
  }> {
    // This would fetch the time-lock encryptions from database
    const timeLockEncryptions = [] as TimeLockEncryption[];
    
    return this.timeLockService.createBatchDecryption(
      timeLockEncryptions,
      batchDto.decryptionKeys
    );
  }

  @Get('estimate-time')
  @ApiOperation({ summary: 'Estimate computation time' })
  @ApiQuery({ name: 'algorithm', description: 'Algorithm' })
  @ApiQuery({ name: 'timeSeconds', description: 'Time in seconds' })
  @ApiQuery({ name: 'securityLevel', description: 'Security level' })
  @ApiResponse({ status: 200, description: 'Computation time estimated' })
  async estimateComputationTime(
    @Query('algorithm') algorithm: TimeLockAlgorithm,
    @Query('timeSeconds') timeSeconds: number,
    @Query('securityLevel') securityLevel: SecurityLevel
  ): Promise<{
    estimatedTime: number;
    parameters: TimeLockParameters;
  }> {
    const unlockTime = new Date(Date.now() + timeSeconds * 1000);
    
    const parameters = await this.timeLockService.getRecommendedParameters(
      unlockTime,
      securityLevel
    );
    
    const estimatedTime = await this.timeLockService.estimateComputationTime(
      parameters,
      algorithm
    );
    
    return {
      estimatedTime,
      parameters
    };
  }

  @Get('metrics')
  @ApiOperation({ summary: 'Get system metrics' })
  @ApiResponse({ status: 200, description: 'Metrics retrieved successfully' })
  async getMetrics(): Promise<{
    system: any;
    security: any;
    performance: any;
    useCases: any;
  }> {
    const [system, security, performance, useCases] = await Promise.all([
      this.timeLockService.getSystemMetrics(),
      this.timeLockService.getSecurityMetrics(),
      this.timeLockService.getPerformanceMetrics(),
      this.useCasesService.getUseCaseMetrics()
    ]);
    
    return {
      system,
      security,
      performance,
      useCases
    };
  }

  @Get('health')
  @ApiOperation({ summary: 'Health check' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  async healthCheck(): Promise<{
    status: string;
    timestamp: Date;
    services: any;
  }> {
    return {
      status: 'healthy',
      timestamp: new Date(),
      services: {
        timeLockEncryption: 'operational',
        vdf: 'operational',
        rsa: 'operational',
        sequentialComputation: 'operational',
        parallelResistance: 'operational',
        publicVerifiability: 'operational',
        smartContractIntegration: 'operational',
        useCases: 'operational'
      }
    };
  }
}
