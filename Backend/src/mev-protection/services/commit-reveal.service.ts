import { Injectable, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import { CommitOrderDto, CommitmentStatus } from '../dto/order.dto';

export interface OrderCommitment {
  id: string;
  orderHash: string;
  userAddress: string;
  side: string;
  pair: string;
  amount: number;
  price?: number;
  orderType: string;
  maxSlippageBps: number;
  commitmentHash: string;
  nonce: string;
  status: CommitmentStatus;
  committedAt: Date;
  revealedAt?: Date;
  executedAt?: Date;
  expiresAt?: Date;
  blockNumber?: number;
  fairOrderingSequence?: number;
}

@Injectable()
export class CommitRevealService {
  private readonly logger = new Logger(CommitRevealService.name);
  private commitments: Map<string, OrderCommitment> = new Map();
  private readonly COMMITMENT_TTL_MS = 5 * 60 * 1000; // 5 minutes
  private readonly FAIR_ORDERING_WINDOW_MS = 1000; // 1 second window for batching

  /**
   * Create commitment for an order (hash-based commitment scheme)
   */
  async commitOrder(dto: CommitOrderDto): Promise<{
    commitmentId: string;
    commitmentHash: string;
    timestamp: Date;
    fairOrderingSequence: number;
  }> {
    // Generate random nonce for commitment
    const nonce = randomBytes(32).toString('hex');
    
    // Create commitment hash: H(order_details || nonce)
    const orderData = JSON.stringify({
      userAddress: dto.userAddress,
      side: dto.side,
      pair: dto.pair,
      amount: dto.amount,
      price: dto.price,
      orderType: dto.orderType,
      maxSlippageBps: dto.maxSlippageBps,
      expiresAt: dto.expiresAt,
    });

    const commitmentHash = this.createCommitmentHash(orderData, nonce);

    // Store commitment
    const commitmentId = `commit_${Date.now()}_${randomBytes(8).toString('hex')}`;
    
    const commitment: OrderCommitment = {
      id: commitmentId,
      orderHash: dto.orderHash,
      userAddress: dto.userAddress,
      side: dto.side,
      pair: dto.pair,
      amount: dto.amount,
      price: dto.price,
      orderType: dto.orderType,
      maxSlippageBps: dto.maxSlippageBps,
      commitmentHash,
      nonce,
      status: CommitmentStatus.COMMITTED,
      committedAt: new Date(),
      expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : 
                 new Date(Date.now() + this.COMMITMENT_TTL_MS),
      fairOrderingSequence: this.assignFairSequence(),
    };

    this.commitments.set(commitmentId, commitment);

    this.logger.log(`Order committed: ${commitmentId}, hash: ${commitmentHash}`);

    return {
      commitmentId,
      commitmentHash,
      timestamp: commitment.committedAt,
      fairOrderingSequence: commitment.fairOrderingSequence!,
    };
  }

  /**
   * Reveal committed order with original data and nonce
   */
  async revealOrder(commitmentId: string, orderData: string, nonce: string): Promise<{
    isValid: boolean;
    commitment: OrderCommitment;
    verificationResult: {
      hashMatches: boolean;
      signatureValid: boolean;
    };
  }> {
    const commitment = this.commitments.get(commitmentId);
    
    if (!commitment) {
      throw new Error('Commitment not found');
    }

    if (commitment.status !== CommitmentStatus.COMMITTED) {
      throw new Error(`Invalid commitment status: ${commitment.status}`);
    }

    // Verify the reveal matches the commitment
    const revealedHash = this.createCommitmentHash(orderData, nonce);
    const hashMatches = revealedHash === commitment.commitmentHash;

    if (!hashMatches) {
      this.logger.warn(`Hash mismatch for commitment ${commitmentId}`);
      commitment.status = CommitmentStatus.CANCELLED;
      return {
        isValid: false,
        commitment,
        verificationResult: {
          hashMatches: false,
          signatureValid: false,
        },
      };
    }

    // Update commitment status
    commitment.status = CommitmentStatus.REVEALED;
    commitment.revealedAt = new Date();

    this.logger.log(`Order revealed successfully: ${commitmentId}`);

    return {
      isValid: true,
      commitment,
      verificationResult: {
        hashMatches: true,
        signatureValid: true, // Would verify actual signature in production
      },
    };
  }

  /**
   * Get commitment by ID
   */
  getCommitment(commitmentId: string): OrderCommitment | undefined {
    return this.commitments.get(commitmentId);
  }

  /**
   * Get all pending commitments for execution
   */
  getPendingCommitments(): OrderCommitment[] {
    return Array.from(this.commitments.values())
      .filter(c => c.status === CommitmentStatus.REVEALED)
      .sort((a, b) => a.fairOrderingSequence! - b.fairOrderingSequence!);
  }

  /**
   * Mark commitment as executed
   */
  markAsExecuted(commitmentId: string, blockNumber?: number): void {
    const commitment = this.commitments.get(commitmentId);
    if (commitment) {
      commitment.status = CommitmentStatus.EXECUTED;
      commitment.executedAt = new Date();
      commitment.blockNumber = blockNumber;
      this.logger.log(`Commitment ${commitmentId} marked as executed`);
    }
  }

  /**
   * Cancel expired or invalid commitments
   */
  cleanupExpiredCommitments(): number {
    const now = Date.now();
    let cleaned = 0;

    this.commitments.forEach((commitment, id) => {
      if (commitment.expiresAt && commitment.expiresAt.getTime() < now) {
        if (commitment.status === CommitmentStatus.COMMITTED || 
            commitment.status === CommitmentStatus.PENDING_COMMIT) {
          commitment.status = CommitmentStatus.EXPIRED;
          cleaned++;
          this.logger.debug(`Expired commitment ${id} cleaned up`);
        }
      }
    });

    return cleaned;
  }

  /**
   * Assign fair ordering sequence number based on time window batching
   */
  private assignFairSequence(): number {
    // Group orders within the same time window
    const windowStart = Math.floor(Date.now() / this.FAIR_ORDERING_WINDOW_MS);
    return windowStart;
  }

  /**
   * Create SHA-256 commitment hash
   */
  private createCommitmentHash(data: string, nonce: string): string {
    return createHash('sha256')
      .update(`${data}:${nonce}`)
      .digest('hex');
  }

  /**
   * Get statistics about commitments
   */
  getCommitmentStats(): {
    total: number;
    byStatus: Record<string, number>;
    pendingExecution: number;
  } {
    const byStatus: Record<string, number> = {};
    let pendingExecution = 0;

    this.commitments.forEach((c) => {
      byStatus[c.status] = (byStatus[c.status] || 0) + 1;
      if (c.status === CommitmentStatus.REVEALED) {
        pendingExecution++;
      }
    });

    return {
      total: this.commitments.size,
      byStatus,
      pendingExecution,
    };
  }
}
