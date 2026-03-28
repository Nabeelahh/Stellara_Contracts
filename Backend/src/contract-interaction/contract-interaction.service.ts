import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import {
  Server,
  TransactionBuilder,
  Account,
  Networks,
  Contract,
  xdr,
  StrKey,
  Keypair,
} from '@stellar/stellar-sdk';

import {
  TransactionRecord,
  TransactionStatus,
  TransactionType,
} from './entities/transaction-record.entity';
import { ContractMetadata, ContractStatus } from './entities/contract-metadata.entity';
import { ContractCallDto, ContractDeployDto, TransactionStatusDto } from './dto/contract-call.dto';
import { AuditService } from '../audit/audit.service';
import { EventBusService } from '../messaging/rabbitmq/event-bus.service';

@Injectable()
export class ContractInteractionService {
  private readonly logger = new Logger(ContractInteractionService.name);
  private server: Server;
  private networkPassphrase: string;

  constructor(
    @InjectRepository(TransactionRecord)
    private transactionRepository: Repository<TransactionRecord>,
    @InjectRepository(ContractMetadata)
    private contractRepository: Repository<ContractMetadata>,
    private configService: ConfigService,
    private dataSource: DataSource,
    private auditService: AuditService,
    private readonly eventBus: EventBusService,
  ) {
    const stellarUrl =
      this.configService.get<string>('STELLAR_HORIZON_URL') ||
      'https://horizon-testnet.stellar.org';
    this.networkPassphrase =
      this.configService.get<string>('STELLAR_NETWORK_PASSPHRASE') || Networks.TESTNET;
    this.server = new Server(stellarUrl);
  }

  async callContract(userId: string, contractCallDto: ContractCallDto): Promise<TransactionRecord> {
    const {
      contractAddress,
      functionName,
      parameters,
      maxFee,
      gasLimit,
      nonce,
      simulateOnly,
      multisigData,
      timeoutSeconds,
    } = contractCallDto;

    try {
      const contract = await this.getContract(contractAddress);
      if (!contract) {
        throw new NotFoundException(`Contract ${contractAddress} not found`);
      }

      const account = await this.server.getAccount(contractCallDto['publicKey'] as string);
      const builder = new TransactionBuilder(account, {
        fee: maxFee?.toString() || '100',
        networkPassphrase: this.networkPassphrase,
      });

      const contractInstance = new Contract(contractAddress);
      const operation = contractInstance.call(
        functionName,
        ...parameters.map((p) => this.convertParameter(p.value, p.type)),
      );

      builder.addOperation(operation);

      if (nonce) {
        builder.setTimeout(30);
      }

      const transaction = builder.build();

      if (simulateOnly) {
        const simulation = await this.server.simulateTransaction(transaction);
        return this.createTransactionRecord(userId, {
          transactionHash: 'simulation',
          transactionType: TransactionType.CONTRACT_CALL,
          status: TransactionStatus.CONFIRMED,
          functionCall: { functionName, parameters, simulateOnly: true },
          resultData: simulation,
          gasUsed: BigInt(simulation.result?.results?.[0]?.units || 0),
        });
      }

      const signedTransaction = multisigData
        ? await this.handleMultisig(transaction, multisigData)
        : await this.signTransaction(transaction, contractCallDto['privateKey'] as string);

      const result = await this.server.sendTransaction(signedTransaction);

      const transactionRecord = await this.createTransactionRecord(userId, {
        transactionHash: result.hash,
        transactionType: TransactionType.CONTRACT_CALL,
        status: TransactionStatus.PENDING,
        functionCall: { functionName, parameters },
        nonce: parseInt(account.sequence),
        isMultisig: !!multisigData,
        multisigData: multisigData || null,
      });

      await this.auditService.log({
        userId,
        action: 'CONTRACT_CALL',
        resource: contractAddress,
        details: { functionName, parameters, transactionHash: result.hash },
      });

      await this.publishDomainEventsForContractCall(transactionRecord, functionName);

      return transactionRecord;
    } catch (error) {
      this.logger.error(`Contract call failed: ${error.message}`, error.stack);
      throw new BadRequestException(`Contract call failed: ${error.message}`);
    }
  }

  async deployContract(userId: string, deployDto: ContractDeployDto): Promise<TransactionRecord> {
    const { wasmCode, contractName, constructorArgs, maxFee, gasLimit, simulateOnly } = deployDto;

    try {
      const account = await this.server.getAccount(deployDto['publicKey'] as string);
      const builder = new TransactionBuilder(account, {
        fee: maxFee?.toString() || '100',
        networkPassphrase: this.networkPassphrase,
      });

      const wasmBuffer = Buffer.from(wasmCode, 'base64');
      const salt = xdr.ScVal.scvBytes32(crypto.getRandomValues(new Uint8Array(32)));

      const createContractOp = xdr.HostFunction.hostFnTypeCreateContractV2({
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIDPreimageFromAddress({
            address: StrKey.decodeEd25519PublicKey(account.accountId()),
            salt,
          }),
        ),
        executable: xdr.ContractExecutable.contractExecutableWasm(wasmBuffer),
      });

      builder.addOperation({
        type: 'invokeHostFunction',
        hostFunction: createContractOp,
      });

      const transaction = builder.build();

      if (simulateOnly) {
        const simulation = await this.server.simulateTransaction(transaction);
        return this.createTransactionRecord(userId, {
          transactionHash: 'simulation',
          transactionType: TransactionType.DEPLOY,
          status: TransactionStatus.CONFIRMED,
          functionCall: { contractName, constructorArgs, simulateOnly: true },
          resultData: simulation,
        });
      }

      const signedTransaction = await this.signTransaction(
        transaction,
        deployDto['privateKey'] as string,
      );
      const result = await this.server.sendTransaction(signedTransaction);

      const transactionRecord = await this.createTransactionRecord(userId, {
        transactionHash: result.hash,
        transactionType: TransactionType.DEPLOY,
        status: TransactionStatus.PENDING,
        functionCall: { contractName, constructorArgs },
        nonce: parseInt(account.sequence),
      });

      await this.auditService.log({
        userId,
        action: 'CONTRACT_DEPLOY',
        resource: contractName,
        details: { transactionHash: result.hash },
      });

      return transactionRecord;
    } catch (error) {
      this.logger.error(`Contract deployment failed: ${error.message}`, error.stack);
      throw new BadRequestException(`Contract deployment failed: ${error.message}`);
    }
  }

  async estimateGas(
    userId: string,
    contractCallDto: ContractCallDto,
  ): Promise<{ gasUsed: bigint; gasPrice: bigint; totalFee: bigint }> {
    try {
      const simulateDto = { ...contractCallDto, simulateOnly: true };
      const simulation = await this.callContract(userId, simulateDto);

      const gasUsed = BigInt(simulation.resultData?.result?.results?.[0]?.units || 100000);
      const gasPrice = BigInt(100); // Base gas price
      const totalFee = gasUsed * gasPrice;

      return {
        gasUsed,
        gasPrice,
        totalFee,
      };
    } catch (error) {
      throw new BadRequestException(`Gas estimation failed: ${error.message}`);
    }
  }

  async getTransactionStatus(userId: string, transactionHash: string): Promise<TransactionRecord> {
    const transaction = await this.transactionRepository.findOne({
      where: { transactionHash, userId },
      relations: ['user'],
    });

    if (!transaction) {
      throw new NotFoundException(`Transaction ${transactionHash} not found`);
    }

    if (transaction.status === TransactionStatus.PENDING) {
      await this.updateTransactionStatus(transaction);
    }

    return transaction;
  }

  async pollTransactionStatus(statusDto: TransactionStatusDto): Promise<TransactionRecord> {
    const { transactionHash, pollingInterval = 5000, maxPollingAttempts = 20 } = statusDto;

    for (let attempt = 0; attempt < maxPollingAttempts; attempt++) {
      const transaction = await this.transactionRepository.findOne({
        where: { transactionHash },
      });

      if (!transaction) {
        throw new NotFoundException(`Transaction ${transactionHash} not found`);
      }

      if (transaction.status !== TransactionStatus.PENDING) {
        return transaction;
      }

      await this.updateTransactionStatus(transaction);

      if (transaction.status !== TransactionStatus.PENDING) {
        return transaction;
      }

      if (attempt < maxPollingAttempts - 1) {
        await new Promise((resolve) => setTimeout(resolve, pollingInterval));
      }
    }

    throw new BadRequestException(
      `Transaction ${transactionHash} polling timeout after ${maxPollingAttempts} attempts`,
    );
  }

  async getUserTransactions(
    userId: string,
    page = 1,
    limit = 20,
  ): Promise<{ transactions: TransactionRecord[]; total: number }> {
    const [transactions, total] = await this.transactionRepository.findAndCount({
      where: { userId },
      order: { createdAt: 'DESC' },
      skip: (page - 1) * limit,
      take: limit,
      relations: ['user'],
    });

    return { transactions, total };
  }

  async registerContract(
    userId: string,
    contractAddress: string,
    contractName: string,
    abiDefinition: any,
  ): Promise<ContractMetadata> {
    const existingContract = await this.contractRepository.findOne({
      where: { contractAddress },
    });

    if (existingContract) {
      throw new ConflictException(`Contract ${contractAddress} already registered`);
    }

    const contract = this.contractRepository.create({
      contractAddress,
      contractName,
      contractVersion: '1.0.0',
      userId,
      abiDefinition,
      functionMetadata: this.extractFunctionMetadata(abiDefinition),
      networkPassphrase: this.networkPassphrase,
      status: ContractStatus.ACTIVE,
    });

    return await this.contractRepository.save(contract);
  }

  @Cron(CronExpression.EVERY_30_SECONDS)
  async updatePendingTransactions(): Promise<void> {
    const pendingTransactions = await this.transactionRepository.find({
      where: { status: TransactionStatus.PENDING },
      take: 50,
    });

    for (const transaction of pendingTransactions) {
      try {
        await this.updateTransactionStatus(transaction);
      } catch (error) {
        this.logger.error(
          `Failed to update transaction ${transaction.transactionHash}: ${error.message}`,
        );
      }
    }
  }

  private async updateTransactionStatus(transaction: TransactionRecord): Promise<void> {
    try {
      const horizonResult = await this.server.getTransaction(transaction.transactionHash);

      if (horizonResult.successful) {
        transaction.status = TransactionStatus.CONFIRMED;
        transaction.blockNumber = horizonResult.ledger;
        transaction.blockTimestamp = new Date(horizonResult.created_at);
        transaction.confirmations = 1;

        if (horizonResult.result_meta_xdr) {
          const meta = xdr.TransactionMeta.fromXDR(horizonResult.result_meta_xdr, 'base64');
          transaction.gasUsed = BigInt(meta.v3()?.txChanges?.length || 0);
        }

        await this.updateContractActivity(transaction.contractId);
      } else {
        transaction.status = TransactionStatus.FAILED;
        transaction.errorData = {
          message: horizonResult.result_xdr,
          code: 'TRANSACTION_FAILED',
        };
      }

      transaction.pollingAttempts += 1;
      transaction.lastPolledAt = new Date();
      await this.transactionRepository.save(transaction);
    } catch (error) {
      if (error.response?.status === 404) {
        transaction.pollingAttempts += 1;
        transaction.lastPolledAt = new Date();

        if (transaction.pollingAttempts > 60) {
          transaction.status = TransactionStatus.TIMEOUT;
        }

        await this.transactionRepository.save(transaction);
      } else {
        throw error;
      }
    }
  }

  private async createTransactionRecord(
    userId: string,
    data: Partial<TransactionRecord>,
  ): Promise<TransactionRecord> {
    const transaction = this.transactionRepository.create({
      userId,
      ...data,
    });
    return await this.transactionRepository.save(transaction);
  }

  private async getContract(contractAddress: string): Promise<ContractMetadata | null> {
    return await this.contractRepository.findOne({
      where: { contractAddress, status: ContractStatus.ACTIVE },
    });
  }

  private async signTransaction(transaction: any, privateKey: string): Promise<any> {
    const keypair = Keypair.fromSecret(privateKey);
    transaction.sign(keypair);
    return transaction;
  }

  private async handleMultisig(transaction: any, multisigData: any): Promise<any> {
    const { signers, requiredSignatures, signedBy = [] } = multisigData;

    for (const signer of signedBy) {
      const keypair = Keypair.fromSecret(signer);
      transaction.sign(keypair);
    }

    return transaction;
  }

  private convertParameter(value: any, type: string): any {
    switch (type) {
      case 'string':
        return xdr.ScVal.scvString(value);
      case 'number':
      case 'uint64':
        return xdr.ScVal.scvU64(BigInt(value));
      case 'boolean':
        return xdr.ScVal.scvBool(value);
      case 'address':
        return xdr.ScVal.scvAddress(
          xdr.Address.scvAddressTypeEd25519(StrKey.decodeEd25519PublicKey(value)),
        );
      default:
        return xdr.ScVal.scvString(JSON.stringify(value));
    }
  }

  private extractFunctionMetadata(abiDefinition: any): Record<string, any> {
    const functions: Record<string, any> = {};

    if (abiDefinition?.spec?.entries) {
      for (const entry of abiDefinition.spec.entries) {
        if (entry.type === 'function') {
          functions[entry.name] = {
            inputs: entry.inputs || [],
            outputs: entry.outputs || [],
            doc: entry.doc || '',
          };
        }
      }
    }

    return functions;
  }

  private async updateContractActivity(contractId: string): Promise<void> {
    if (!contractId) return;

    await this.contractRepository.increment({ id: contractId }, 'totalTransactions', 1);
    await this.contractRepository.update(
      { id: contractId },
      {
        lastActivityAt: new Date(),
      },
    );
  }

  private async publishDomainEventsForContractCall(
    transactionRecord: TransactionRecord,
    functionName: string,
  ): Promise<void> {
    const fn = String(functionName || '').toLowerCase();
    const params = transactionRecord.functionCall?.parameters ?? [];

    if (fn === 'trade' || fn.includes('trade')) {
      await this.eventBus.publish('TradeExecuted', {
        transactionId: transactionRecord.id,
        transactionHash: transactionRecord.transactionHash,
        userId: transactionRecord.userId,
        contractId: transactionRecord.contractId,
        functionName,
        parameters: params,
        createdAt: transactionRecord.createdAt?.toISOString?.() ?? new Date().toISOString(),
      });
      return;
    }

    if (fn.includes('payment') || fn.includes('pay') || fn.includes('contribution')) {
      await this.eventBus.publish('PaymentProcessed', {
        transactionId: transactionRecord.id,
        transactionHash: transactionRecord.transactionHash,
        userId: transactionRecord.userId,
        contractId: transactionRecord.contractId,
        functionName,
        parameters: params,
        createdAt: transactionRecord.createdAt?.toISOString?.() ?? new Date().toISOString(),
      });
    }
  }
}
