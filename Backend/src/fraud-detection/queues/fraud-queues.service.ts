import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { FraudAssessment, FraudDecision } from '../scoring/fraud-scoring.service';

/**
 * Declined Transaction Record
 */
export interface DeclinedTransaction {
  transactionId: string;
  userId: string;
  amount: number;
  currency: string;
  fraudScore: number;
  reason: string;
  declinedAt: Date;
  notificationSent: boolean;
}

/**
 * Manual Review Case
 */
export interface ManualReviewCase {
  caseId: string;
  transactionId: string;
  userId: string;
  amount: number;
  currency: string;
  fraudScore: number;
  confidence: number;
  explanation: string[];
  status: ReviewStatus;
  priority: ReviewPriority;
  assignedTo?: string;
  createdAt: Date;
  reviewedAt?: Date;
  reviewDecision?: ReviewDecision;
  reviewNotes?: string;
}

/**
 * Review Status
 */
export enum ReviewStatus {
  PENDING = 'pending',
  IN_REVIEW = 'in_review',
  APPROVED = 'approved',
  DECLINED = 'declined',
  ESCALATED = 'escalated',
}

/**
 * Review Priority
 */
export enum ReviewPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Review Decision
 */
export enum ReviewDecision {
  APPROVE = 'approve',
  DECLINE = 'decline',
  ESCALATE = 'escalate',
  REQUEST_INFO = 'request_info',
}

/**
 * Fraud Queues Service
 * 
 * Manages the auto-decline and manual review queues.
 * Uses Bull queue for reliable job processing.
 */
@Injectable()
export class FraudQueuesService {
  private readonly logger = new Logger(FraudQueuesService.name);
  
  // In-memory store for manual review cases (in production, use database)
  private reviewCases: Map<string, ManualReviewCase> = new Map();
  private declinedTransactions: Map<string, DeclinedTransaction> = new Map();

  constructor(
    @InjectQueue('fraud-declined') private readonly declineQueue: Queue,
    @InjectQueue('fraud-review') private readonly reviewQueue: Queue,
  ) {}

  /**
   * Process a fraud assessment and route to appropriate queue
   */
  async processAssessment(
    assessment: FraudAssessment,
    transactionDetails: {
      userId: string;
      amount: number;
      currency: string;
    }
  ): Promise<void> {
    switch (assessment.decision) {
      case FraudDecision.DECLINE:
        await this.queueForDecline(assessment, transactionDetails);
        break;
      
      case FraudDecision.REVIEW:
        await this.queueForReview(assessment, transactionDetails);
        break;
      
      case FraudDecision.APPROVE:
        // No queue needed for approved transactions
        this.logger.debug(`Transaction ${assessment.transactionId} approved`);
        break;
    }
  }

  /**
   * Queue transaction for auto-decline
   */
  private async queueForDecline(
    assessment: FraudAssessment,
    details: { userId: string; amount: number; currency: string }
  ): Promise<void> {
    const declinedTx: DeclinedTransaction = {
      transactionId: assessment.transactionId,
      userId: details.userId,
      amount: details.amount,
      currency: details.currency,
      fraudScore: assessment.score,
      reason: assessment.explanation.join('; '),
      declinedAt: new Date(),
      notificationSent: false,
    };

    // Store in memory (use database in production)
    this.declinedTransactions.set(assessment.transactionId, declinedTx);

    // Add to processing queue
    await this.declineQueue.add('process-declined', {
      transaction: declinedTx,
      assessment,
    }, {
      priority: assessment.score, // Higher score = higher priority
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 1000,
      },
    });

    this.logger.log(
      `Transaction ${assessment.transactionId} queued for decline (score: ${assessment.score})`
    );
  }

  /**
   * Queue transaction for manual review
   */
  private async queueForReview(
    assessment: FraudAssessment,
    details: { userId: string; amount: number; currency: string }
  ): Promise<void> {
    const caseId = `CASE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const reviewCase: ManualReviewCase = {
      caseId,
      transactionId: assessment.transactionId,
      userId: details.userId,
      amount: details.amount,
      currency: details.currency,
      fraudScore: assessment.score,
      confidence: assessment.confidence,
      explanation: assessment.explanation,
      status: ReviewStatus.PENDING,
      priority: this.calculatePriority(assessment.score, details.amount),
      createdAt: new Date(),
    };

    // Store in memory (use database in production)
    this.reviewCases.set(caseId, reviewCase);

    // Add to review queue
    await this.reviewQueue.add('process-review', {
      case: reviewCase,
      assessment,
    }, {
      priority: this.priorityToNumber(reviewCase.priority),
      attempts: 5,
      backoff: {
        type: 'exponential',
        delay: 2000,
      },
    });

    this.logger.log(
      `Case ${caseId} created for manual review (score: ${assessment.score}, priority: ${reviewCase.priority})`
    );
  }

  /**
   * Get all pending review cases
   */
  getPendingReviewCases(): ManualReviewCase[] {
    return Array.from(this.reviewCases.values())
      .filter(c => c.status === ReviewStatus.PENDING || c.status === ReviewStatus.IN_REVIEW)
      .sort((a, b) => {
        // Sort by priority first, then by creation time
        const priorityDiff = this.priorityToNumber(b.priority) - this.priorityToNumber(a.priority);
        if (priorityDiff !== 0) return priorityDiff;
        return a.createdAt.getTime() - b.createdAt.getTime();
      });
  }

  /**
   * Get a specific review case
   */
  getReviewCase(caseId: string): ManualReviewCase | undefined {
    return this.reviewCases.get(caseId);
  }

  /**
   * Assign a case to a reviewer
   */
  async assignCase(caseId: string, reviewerId: string): Promise<ManualReviewCase> {
    const case_ = this.reviewCases.get(caseId);
    
    if (!case_) {
      throw new Error(`Review case ${caseId} not found`);
    }

    if (case_.status !== ReviewStatus.PENDING) {
      throw new Error(`Case ${caseId} is not pending`);
    }

    case_.assignedTo = reviewerId;
    case_.status = ReviewStatus.IN_REVIEW;

    this.logger.log(`Case ${caseId} assigned to reviewer ${reviewerId}`);

    return case_;
  }

  /**
   * Submit review decision
   */
  async submitReviewDecision(
    caseId: string,
    decision: ReviewDecision,
    notes?: string
  ): Promise<ManualReviewCase> {
    const case_ = this.reviewCases.get(caseId);
    
    if (!case_) {
      throw new Error(`Review case ${caseId} not found`);
    }

    if (case_.status !== ReviewStatus.IN_REVIEW) {
      throw new Error(`Case ${caseId} is not in review`);
    }

    case_.reviewDecision = decision;
    case_.reviewNotes = notes;
    case_.reviewedAt = new Date();

    // Update status based on decision
    switch (decision) {
      case ReviewDecision.APPROVE:
        case_.status = ReviewStatus.APPROVED;
        break;
      case ReviewDecision.DECLINE:
        case_.status = ReviewStatus.DECLINED;
        break;
      case ReviewDecision.ESCALATE:
        case_.status = ReviewStatus.ESCALATED;
        case_.priority = ReviewPriority.CRITICAL;
        break;
    }

    this.logger.log(`Case ${caseId} reviewed with decision: ${decision}`);

    return case_;
  }

  /**
   * Get declined transactions
   */
  getDeclinedTransactions(
    options: {
      userId?: string;
      from?: Date;
      to?: Date;
      limit?: number;
    } = {}
  ): DeclinedTransaction[] {
    let transactions = Array.from(this.declinedTransactions.values());

    if (options.userId) {
      transactions = transactions.filter(t => t.userId === options.userId);
    }

    if (options.from) {
      transactions = transactions.filter(t => t.declinedAt >= options.from!);
    }

    if (options.to) {
      transactions = transactions.filter(t => t.declinedAt <= options.to!);
    }

    // Sort by date descending
    transactions.sort((a, b) => b.declinedAt.getTime() - a.declinedAt.getTime());

    if (options.limit) {
      transactions = transactions.slice(0, options.limit);
    }

    return transactions;
  }

  /**
   * Get queue statistics
   */
  async getQueueStats(): Promise<{
    declined: {
      waiting: number;
      active: number;
      completed: number;
      failed: number;
    };
    review: {
      waiting: number;
      active: number;
      completed: number;
      failed: number;
      pending: number;
      inReview: number;
    };
  }> {
    const [declinedWaiting, declinedActive, declinedCompleted, declinedFailed] =
      await Promise.all([
        this.declineQueue.getWaitingCount(),
        this.declineQueue.getActiveCount(),
        this.declineQueue.getCompletedCount(),
        this.declineQueue.getFailedCount(),
      ]);

    const [reviewWaiting, reviewActive, reviewCompleted, reviewFailed] =
      await Promise.all([
        this.reviewQueue.getWaitingCount(),
        this.reviewQueue.getActiveCount(),
        this.reviewQueue.getCompletedCount(),
        this.reviewQueue.getFailedCount(),
      ]);

    const pendingCases = Array.from(this.reviewCases.values()).filter(
      c => c.status === ReviewStatus.PENDING
    ).length;

    const inReviewCases = Array.from(this.reviewCases.values()).filter(
      c => c.status === ReviewStatus.IN_REVIEW
    ).length;

    return {
      declined: {
        waiting: declinedWaiting,
        active: declinedActive,
        completed: declinedCompleted,
        failed: declinedFailed,
      },
      review: {
        waiting: reviewWaiting,
        active: reviewActive,
        completed: reviewCompleted,
        failed: reviewFailed,
        pending: pendingCases,
        inReview: inReviewCases,
      },
    };
  }

  /**
   * Calculate review priority based on score and amount
   */
  private calculatePriority(score: number, amount: number): ReviewPriority {
    if (score >= 80 || amount >= 10000) {
      return ReviewPriority.CRITICAL;
    }
    if (score >= 65 || amount >= 5000) {
      return ReviewPriority.HIGH;
    }
    if (score >= 55 || amount >= 1000) {
      return ReviewPriority.MEDIUM;
    }
    return ReviewPriority.LOW;
  }

  /**
   * Convert priority to numeric value for sorting
   */
  private priorityToNumber(priority: ReviewPriority): number {
    const priorities: Record<ReviewPriority, number> = {
      [ReviewPriority.LOW]: 1,
      [ReviewPriority.MEDIUM]: 2,
      [ReviewPriority.HIGH]: 3,
      [ReviewPriority.CRITICAL]: 4,
    };
    return priorities[priority];
  }
}
