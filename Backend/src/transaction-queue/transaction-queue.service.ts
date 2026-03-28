import { Cron } from '@nestjs/schedule';
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { EnqueueTransactionDto, QueuePriorityDto, QueueSummaryDto } from './dto/transaction-queue.dto';
import { TransactionGatewayService } from './transaction-gateway.service';

type QueueItem = any;
type QueuePriority = 'LOW' | 'NORMAL' | 'HIGH' | 'CRITICAL';
type QueueStatus =
  | 'QUEUED'
  | 'PROCESSING'
  | 'SUBMITTED'
  | 'STUCK'
  | 'CONFIRMED'
  | 'FAILED'
  | 'CANCELLED'
  | 'DEAD_LETTER';
type NonceFailureType = 'NONCE_TOO_LOW' | 'NONCE_TOO_HIGH' | 'NONCE_DUPLICATE' | 'NONCE_GENERIC' | 'NONE';

@Injectable()
export class TransactionQueueService {
  private readonly logger = new Logger(TransactionQueueService.name);
  private readonly network: string;
  private readonly processingBatchSize: number;
  private readonly pollBatchSize: number;
  private readonly stuckThresholdMs: number;
  private readonly baseFeeBid: bigint;

  private queueTickInProgress = false;
  private pollTickInProgress = false;

  private readonly priorityWeight: Record<QueuePriority, number> = {
    LOW: 1,
    NORMAL: 2,
    HIGH: 3,
    CRITICAL: 4,
  };

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly gateway: TransactionGatewayService,
  ) {
    this.network = this.configService.get<string>('STELLAR_NETWORK', 'testnet');
    this.processingBatchSize = this.configService.get<number>('TX_QUEUE_BATCH_SIZE', 25);
    this.pollBatchSize = this.configService.get<number>('TX_QUEUE_POLL_BATCH_SIZE', 50);
    this.stuckThresholdMs = this.configService.get<number>('TX_QUEUE_STUCK_THRESHOLD_MS', 120_000);
    this.baseFeeBid = BigInt(this.configService.get<number>('TX_QUEUE_BASE_FEE_BID', 100));
  }

  async enqueue(dto: EnqueueTransactionDto): Promise<QueueItem> {
    const idempotencyKey = dto.idempotencyKey || this.buildIdempotencyKey(dto);
    const existing = await (this.prisma as any).blockchainTransactionQueueItem.findUnique({
      where: { idempotencyKey },
    });

    if (existing) {
      return existing;
    }

    try {
      const created = await (this.prisma as any).blockchainTransactionQueueItem.create({
        data: {
          idempotencyKey,
          signerAddress: dto.signerAddress,
          contractAddress: dto.contractAddress,
          functionName: dto.functionName,
          payload: dto.payload,
          metadata: dto.metadata ?? null,
          priority: dto.priority ?? QueuePriorityDto.NORMAL,
          status: 'QUEUED',
          nonce: dto.nonce !== undefined ? BigInt(dto.nonce) : null,
          feeBid: dto.requestedFeeBid !== undefined ? BigInt(dto.requestedFeeBid) : null,
          maxRetries: dto.maxRetries ?? 5,
          nextAttemptAt: new Date(),
        },
      });

      return created;
    } catch (error) {
      const maybeCode = (error as any)?.code;
      if (maybeCode === 'P2002') {
        const duplicate = await (this.prisma as any).blockchainTransactionQueueItem.findUnique({
          where: { idempotencyKey },
        });
        if (duplicate) {
          return duplicate;
        }
      }
      throw error;
    }
  }

  async getById(id: string): Promise<QueueItem> {
    const item = await (this.prisma as any).blockchainTransactionQueueItem.findUnique({
      where: { id },
      include: {
        attempts: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!item) {
      throw new NotFoundException(`Queue item ${id} not found`);
    }

    return item;
  }

  async getByIdempotencyKey(idempotencyKey: string): Promise<QueueItem> {
    const item = await (this.prisma as any).blockchainTransactionQueueItem.findUnique({
      where: { idempotencyKey },
      include: {
        attempts: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!item) {
      throw new NotFoundException(`Queue item for idempotency key ${idempotencyKey} not found`);
    }

    return item;
  }

  async getSummary(): Promise<QueueSummaryDto> {
    const statuses: QueueStatus[] = [
      'QUEUED',
      'PROCESSING',
      'SUBMITTED',
      'STUCK',
      'CONFIRMED',
      'FAILED',
      'DEAD_LETTER',
    ];

    const result = await Promise.all(
      statuses.map((status) =>
        (this.prisma as any).blockchainTransactionQueueItem.count({ where: { status } }),
      ),
    );

    return {
      queued: result[0],
      processing: result[1],
      submitted: result[2],
      stuck: result[3],
      confirmed: result[4],
      failed: result[5],
      deadLetter: result[6],
    };
  }

  async retryNow(id: string): Promise<QueueItem> {
    await this.assertItemExists(id);

    return (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id },
      data: {
        status: 'QUEUED',
        lastError: null,
        nextAttemptAt: new Date(),
      },
    });
  }

  async cancel(id: string): Promise<QueueItem> {
    const item = await this.assertItemExists(id);
    if (item.status === 'CONFIRMED') {
      return item;
    }

    return (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id },
      data: {
        status: 'CANCELLED',
      },
    });
  }

  async getSignerNonceState(signerAddress: string): Promise<any> {
    const nonceState = await (this.prisma as any).blockchainNonceState.findUnique({
      where: { signerAddress },
    });

    if (nonceState) {
      return nonceState;
    }

    return (this.prisma as any).blockchainNonceState.create({
      data: {
        signerAddress,
        nextNonce: BigInt(0),
      },
    });
  }

  @Cron('*/5 * * * * *')
  async processQueuedTransactions(): Promise<void> {
    if (this.queueTickInProgress) {
      return;
    }

    this.queueTickInProgress = true;

    try {
      const now = new Date();
      const candidates = await (this.prisma as any).blockchainTransactionQueueItem.findMany({
        where: {
          status: { in: ['QUEUED', 'FAILED', 'STUCK'] },
          OR: [{ nextAttemptAt: null }, { nextAttemptAt: { lte: now } }],
        },
        take: this.processingBatchSize * 3,
      });

      const sorted = candidates
        .filter((item: QueueItem) => (item.retryCount || 0) < (item.maxRetries || 5))
        .sort((left: QueueItem, right: QueueItem) => {
          const priorityDiff =
            this.priorityWeight[(right.priority || 'NORMAL') as QueuePriority] -
            this.priorityWeight[(left.priority || 'NORMAL') as QueuePriority];
          if (priorityDiff !== 0) {
            return priorityDiff;
          }
          return new Date(left.createdAt).getTime() - new Date(right.createdAt).getTime();
        })
        .slice(0, this.processingBatchSize);

      for (const item of sorted) {
        try {
          await this.processSingleItem(item);
        } catch (error) {
          this.logger.error(
            `Failed to process queue item ${item.id}: ${error.message}`,
            error.stack,
          );
        }
      }
    } catch (error) {
      this.logger.error(`Queue processing tick failed: ${error.message}`, error.stack);
    } finally {
      this.queueTickInProgress = false;
    }
  }

  @Cron('*/15 * * * * *')
  async pollSubmittedTransactions(): Promise<void> {
    if (this.pollTickInProgress) {
      return;
    }

    this.pollTickInProgress = true;

    try {
      const submitted = await (this.prisma as any).blockchainTransactionQueueItem.findMany({
        where: {
          status: { in: ['SUBMITTED', 'STUCK'] },
          txHash: { not: null },
        },
        orderBy: { submittedAt: 'asc' },
        take: this.pollBatchSize,
      });

      for (const item of submitted) {
        try {
          await this.pollSingleItem(item);
        } catch (error) {
          this.logger.error(
            `Failed to poll queue item ${item.id} (${item.txHash}): ${error.message}`,
            error.stack,
          );
        }
      }
    } catch (error) {
      this.logger.error(`Submitted polling tick failed: ${error.message}`, error.stack);
    } finally {
      this.pollTickInProgress = false;
    }
  }

  private async processSingleItem(item: QueueItem): Promise<void> {
    const fresh = await this.assertItemExists(item.id);
    if (!['QUEUED', 'FAILED', 'STUCK'].includes(fresh.status)) {
      return;
    }

    await (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id: item.id },
      data: {
        status: 'PROCESSING',
        processingStartedAt: new Date(),
      },
    });

    const attemptNumber = await this.getNextAttemptNumber(item.id);
    const nonce = await this.allocateNonce(fresh);
    const feeBid = this.computeDynamicFeeBid(fresh);

    try {
      const submission = await this.gateway.submitTransaction({
        signerAddress: fresh.signerAddress,
        contractAddress: fresh.contractAddress,
        functionName: fresh.functionName,
        payload: fresh.payload,
        nonce,
        feeBid,
      });

      await (this.prisma as any).blockchainTransactionAttempt.create({
        data: {
          queueItemId: fresh.id,
          attemptNumber,
          nonce,
          feeBid,
          txHash: submission.txHash,
          status: 'SUBMITTED',
          rawResponse: submission.raw,
        },
      });

      await (this.prisma as any).blockchainTransactionQueueItem.update({
        where: { id: fresh.id },
        data: {
          status: 'SUBMITTED',
          txHash: submission.txHash,
          nonce,
          feeBid,
          submittedAt: new Date(),
          nextAttemptAt: new Date(Date.now() + 15_000),
          lastError: null,
        },
      });

      await this.advanceNonceState(fresh.signerAddress, nonce, submission.txHash);
    } catch (error) {
      await this.handleSubmissionFailure(fresh, error, attemptNumber, nonce, feeBid);
    }
  }

  private async pollSingleItem(item: QueueItem): Promise<void> {
    const txHash = item.txHash as string | null;
    if (!txHash) {
      return;
    }

    const poll = await this.gateway.getTransactionStatus(txHash);

    if (poll.status === 'CONFIRMED') {
      const parsed = this.parseTransactionResult(item, poll.raw);

      await (this.prisma as any).blockchainTransactionQueueItem.update({
        where: { id: item.id },
        data: {
          status: 'CONFIRMED',
          result: parsed,
          confirmedAt: new Date(),
          nextAttemptAt: null,
          lastError: null,
        },
      });

      await this.indexParsedResult(item, parsed);
      return;
    }

    if (poll.status === 'FAILED') {
      const nextAttempt = item.retryCount + 1;
      await this.handlePolledFailure(item, nextAttempt, poll.raw);
      return;
    }

    const submittedAtMs = item.submittedAt ? new Date(item.submittedAt).getTime() : 0;
    const isStuck = submittedAtMs > 0 && Date.now() - submittedAtMs >= this.stuckThresholdMs;

    if (isStuck) {
      await this.bumpFeeForStuckTransaction(item);
    }
  }

  private async handlePolledFailure(
    item: QueueItem,
    nextAttempt: number,
    raw: Record<string, unknown>,
  ): Promise<void> {
    const maxRetries = item.maxRetries ?? 5;
    if (nextAttempt > maxRetries) {
      await (this.prisma as any).blockchainTransactionQueueItem.update({
        where: { id: item.id },
        data: {
          status: 'DEAD_LETTER',
          retryCount: nextAttempt,
          lastError: 'Transaction failed after max retries',
          result: raw,
        },
      });
      return;
    }

    const backoffMs = this.computeBackoffMs(nextAttempt);
    await (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id: item.id },
      data: {
        status: 'FAILED',
        retryCount: nextAttempt,
        lastError: 'Transaction failed on polling',
        nextAttemptAt: new Date(Date.now() + backoffMs),
        result: raw,
      },
    });
  }

  private async bumpFeeForStuckTransaction(item: QueueItem): Promise<void> {
    const currentFee = BigInt(item.feeBid || this.baseFeeBid);
    let bumped = (currentFee * BigInt(12)) / BigInt(10) + BigInt(50);
    if (item.maxFee) {
      const maxFee = BigInt(item.maxFee);
      if (bumped > maxFee) {
        bumped = maxFee;
      }
    }
    const txHash = item.txHash as string | null;

    if (!txHash) {
      return;
    }

    const response = await this.gateway.bumpFee(txHash, bumped);
    if (!response.accepted) {
      this.logger.warn(`Fee bump rejected for tx ${txHash}`);
      return;
    }

    const attemptNumber = await this.getNextAttemptNumber(item.id);
    await (this.prisma as any).blockchainTransactionAttempt.create({
      data: {
        queueItemId: item.id,
        attemptNumber,
        nonce: item.nonce,
        feeBid: bumped,
        txHash,
        status: 'STUCK',
        rawResponse: {
          action: 'fee_bump',
          accepted: true,
          bumpedFeeBid: bumped.toString(),
        },
      },
    });

    await (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id: item.id },
      data: {
        status: 'STUCK',
        feeBid: bumped,
        nextAttemptAt: new Date(Date.now() + 15_000),
      },
    });
  }

  private async handleSubmissionFailure(
    item: QueueItem,
    error: any,
    attemptNumber: number,
    nonce: bigint,
    feeBid: bigint,
  ): Promise<void> {
    const message = String(error?.message || 'Unknown submission failure');
    const nonceFailureType = this.classifyNonceError(message);
    const isNonceFailure = nonceFailureType !== 'NONE';
    const nextRetryCount = (item.retryCount || 0) + 1;
    const maxRetries = item.maxRetries ?? 5;

    await (this.prisma as any).blockchainTransactionAttempt.create({
      data: {
        queueItemId: item.id,
        attemptNumber,
        nonce,
        feeBid,
        status: 'FAILED',
        error: message,
      },
    });

    if (isNonceFailure) {
      await this.recoverNonceState(item.signerAddress, nonce, nonceFailureType);
    }

    if (nextRetryCount > maxRetries) {
      await (this.prisma as any).blockchainTransactionQueueItem.update({
        where: { id: item.id },
        data: {
          status: 'DEAD_LETTER',
          retryCount: nextRetryCount,
          lastError: message,
          nextAttemptAt: null,
        },
      });
      return;
    }

    const retryAt = new Date(Date.now() + this.computeBackoffMs(nextRetryCount));
    await (this.prisma as any).blockchainTransactionQueueItem.update({
      where: { id: item.id },
      data: {
        status: 'FAILED',
        retryCount: nextRetryCount,
        lastError: message,
        nextAttemptAt: retryAt,
        feeBid: (feeBid * BigInt(11)) / BigInt(10) + BigInt(25),
      },
    });
  }

  private buildIdempotencyKey(dto: EnqueueTransactionDto): string {
    const canonical = JSON.stringify({
      signerAddress: dto.signerAddress,
      contractAddress: dto.contractAddress,
      functionName: dto.functionName,
      payload: dto.payload,
      metadata: dto.metadata ?? null,
    });

    return createHash('sha256').update(canonical).digest('hex');
  }

  private computeDynamicFeeBid(item: QueueItem): bigint {
    const priority: QueuePriority = (item.priority || 'NORMAL') as QueuePriority;
    const priorityBoost: Record<QueuePriority, bigint> = {
      LOW: BigInt(0),
      NORMAL: BigInt(25),
      HIGH: BigInt(60),
      CRITICAL: BigInt(120),
    };

    const retryBoost = BigInt((item.retryCount || 0) * 40);
    const payloadSizeBoost = BigInt(
      Math.min(100, Math.floor(JSON.stringify(item.payload || {}).length / 40)),
    );
    const previousFee = item.feeBid ? BigInt(item.feeBid) : BigInt(0);

    let computed = this.baseFeeBid + priorityBoost[priority] + retryBoost + payloadSizeBoost;
    if (previousFee > computed) {
      computed = previousFee;
    }

    if (item.maxFee) {
      const maxFee = BigInt(item.maxFee);
      if (computed > maxFee) {
        return maxFee;
      }
    }

    return computed;
  }

  private async allocateNonce(item: QueueItem): Promise<bigint> {
    if (item.nonce !== null && item.nonce !== undefined) {
      return BigInt(item.nonce);
    }

    const existingState = await (this.prisma as any).blockchainNonceState.findUnique({
      where: { signerAddress: item.signerAddress },
    });

    if (existingState) {
      return BigInt(existingState.nextNonce);
    }

    const created = await (this.prisma as any).blockchainNonceState.create({
      data: {
        signerAddress: item.signerAddress,
        nextNonce: BigInt(0),
      },
    });

    return BigInt(created.nextNonce);
  }

  private async advanceNonceState(
    signerAddress: string,
    usedNonce: bigint,
    txHash: string,
  ): Promise<void> {
    await (this.prisma as any).blockchainNonceState.upsert({
      where: { signerAddress },
      update: {
        nextNonce: usedNonce + BigInt(1),
        lastUsedNonce: usedNonce,
        lastTxHash: txHash,
      },
      create: {
        signerAddress,
        nextNonce: usedNonce + BigInt(1),
        lastUsedNonce: usedNonce,
        lastTxHash: txHash,
      },
    });
  }

  private async recoverNonceState(
    signerAddress: string,
    failedNonce: bigint,
    failureType: NonceFailureType,
  ): Promise<void> {
    const state = await (this.prisma as any).blockchainNonceState.findUnique({
      where: { signerAddress },
    });

    if (!state) {
      const initialNextNonce =
        failureType === 'NONCE_TOO_HIGH' ? failedNonce : failedNonce + BigInt(1);
      await (this.prisma as any).blockchainNonceState.create({
        data: {
          signerAddress,
          nextNonce: initialNextNonce,
          lastUsedNonce: failedNonce,
        },
      });
      return;
    }

    const currentNext = BigInt(state.nextNonce);

    if (failureType === 'NONCE_TOO_HIGH') {
      if (currentNext > failedNonce) {
        await (this.prisma as any).blockchainNonceState.update({
          where: { signerAddress },
          data: {
            nextNonce: failedNonce,
            lastUsedNonce: state.lastUsedNonce,
          },
        });
      }
      return;
    }

    if (currentNext <= failedNonce || failureType === 'NONCE_DUPLICATE' || failureType === 'NONCE_TOO_LOW') {
      await (this.prisma as any).blockchainNonceState.update({
        where: { signerAddress },
        data: {
          nextNonce: failedNonce + BigInt(1),
          lastUsedNonce: failedNonce,
        },
      });
    }
  }

  private async indexParsedResult(item: QueueItem, parsed: Record<string, unknown>): Promise<void> {
    const txHash = String(item.txHash || '');
    if (!txHash) {
      return;
    }

    try {
      await (this.prisma as any).processedEvent.upsert({
        where: { eventId: `tx:${txHash}` },
        update: {
          decodedData: parsed,
          eventType: 'transaction_confirmed',
        },
        create: {
          eventId: `tx:${txHash}`,
          network: this.network,
          ledgerSeq: Number(parsed.ledgerSeq || 0),
          contractId: item.contractAddress,
          eventType: 'transaction_confirmed',
          transactionHash: txHash,
          contractType: 'stellar_contract',
          decodedData: parsed,
          abiVersion: 'queue-v1',
        },
      });
    } catch (error) {
      this.logger.warn(`Failed to index parsed transaction result for ${txHash}: ${error.message}`);
    }
  }

  private parseTransactionResult(
    item: QueueItem,
    raw: Record<string, unknown>,
  ): Record<string, unknown> {
    return {
      txHash: item.txHash,
      signerAddress: item.signerAddress,
      contractAddress: item.contractAddress,
      functionName: item.functionName,
      status: 'CONFIRMED',
      ledgerSeq: raw['ledgerSeq'] || 0,
      confirmedAt: new Date().toISOString(),
      raw,
    };
  }

  private classifyNonceError(message: string): NonceFailureType {
    const normalized = message.toLowerCase();
    const mentionsNonce = normalized.includes('nonce') || normalized.includes('sequence');
    if (!mentionsNonce && !normalized.includes('duplicate')) {
      return 'NONE';
    }

    if (
      normalized.includes('too low') ||
      normalized.includes('already used') ||
      normalized.includes('bad seq')
    ) {
      return 'NONCE_TOO_LOW';
    }

    if (normalized.includes('too high') || normalized.includes('future')) {
      return 'NONCE_TOO_HIGH';
    }

    if (normalized.includes('duplicate')) {
      return 'NONCE_DUPLICATE';
    }

    return mentionsNonce ? 'NONCE_GENERIC' : 'NONE';
  }

  private computeBackoffMs(retryCount: number): number {
    const capped = Math.min(retryCount, 8);
    return Math.min(300_000, 5_000 * 2 ** (capped - 1));
  }

  private async getNextAttemptNumber(queueItemId: string): Promise<number> {
    const count = await (this.prisma as any).blockchainTransactionAttempt.count({
      where: { queueItemId },
    });
    return count + 1;
  }

  private async assertItemExists(id: string): Promise<QueueItem> {
    const item = await (this.prisma as any).blockchainTransactionQueueItem.findUnique({
      where: { id },
    });

    if (!item) {
      throw new NotFoundException(`Queue item ${id} not found`);
    }

    return item;
  }
}
