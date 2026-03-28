import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ContractInteractionService } from './contract-interaction.service';
import { ContractCallDto, ContractDeployDto, TransactionStatusDto } from './dto/contract-call.dto';
import { TransactionRecord } from './entities/transaction-record.entity';

@ApiTags('Contract Interaction')
@Controller('contract-interaction')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class ContractInteractionController {
  constructor(private readonly contractInteractionService: ContractInteractionService) {}

  @Post('call')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Call a smart contract function' })
  @ApiResponse({
    status: 200,
    description: 'Transaction submitted successfully',
    type: TransactionRecord,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async callContract(
    @Request() req: any,
    @Body() contractCallDto: ContractCallDto,
  ): Promise<TransactionRecord> {
    return await this.contractInteractionService.callContract(req.user.userId, contractCallDto);
  }

  @Post('deploy')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Deploy a new smart contract' })
  @ApiResponse({
    status: 200,
    description: 'Contract deployment submitted',
    type: TransactionRecord,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async deployContract(
    @Request() req: any,
    @Body() deployDto: ContractDeployDto,
  ): Promise<TransactionRecord> {
    return await this.contractInteractionService.deployContract(req.user.userId, deployDto);
  }

  @Post('estimate-gas')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Estimate gas for contract call' })
  @ApiResponse({ status: 200, description: 'Gas estimation successful' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async estimateGas(
    @Request() req: any,
    @Body() contractCallDto: ContractCallDto,
  ): Promise<{ gasUsed: bigint; gasPrice: bigint; totalFee: bigint }> {
    return await this.contractInteractionService.estimateGas(req.user.userId, contractCallDto);
  }

  @Get('transaction/:hash')
  @ApiOperation({ summary: 'Get transaction status by hash' })
  @ApiResponse({
    status: 200,
    description: 'Transaction details retrieved',
    type: TransactionRecord,
  })
  @ApiResponse({ status: 404, description: 'Transaction not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getTransactionStatus(
    @Request() req: any,
    @Param('hash') transactionHash: string,
  ): Promise<TransactionRecord> {
    return await this.contractInteractionService.getTransactionStatus(
      req.user.userId,
      transactionHash,
    );
  }

  @Post('poll-transaction')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Poll transaction status until completion' })
  @ApiResponse({ status: 200, description: 'Transaction completed', type: TransactionRecord })
  @ApiResponse({ status: 400, description: 'Polling timeout or error' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async pollTransactionStatus(@Body() statusDto: TransactionStatusDto): Promise<TransactionRecord> {
    return await this.contractInteractionService.pollTransactionStatus(statusDto);
  }

  @Get('transactions')
  @ApiOperation({ summary: 'Get user transactions with pagination' })
  @ApiResponse({ status: 200, description: 'Transactions retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getUserTransactions(
    @Request() req: any,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 20,
  ): Promise<{ transactions: TransactionRecord[]; total: number }> {
    return await this.contractInteractionService.getUserTransactions(req.user.userId, page, limit);
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a contract with metadata' })
  @ApiResponse({ status: 201, description: 'Contract registered successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async registerContract(
    @Request() req: any,
    @Body()
    registerDto: {
      contractAddress: string;
      contractName: string;
      abiDefinition: any;
    },
  ): Promise<any> {
    return await this.contractInteractionService.registerContract(
      req.user.userId,
      registerDto.contractAddress,
      registerDto.contractName,
      registerDto.abiDefinition,
    );
  }
}
