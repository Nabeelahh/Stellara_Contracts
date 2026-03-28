import { Injectable, Logger } from '@nestjs/common';
import { FeatureExtractor, Transaction, UserProfile, FraudFeatures } from '../features/feature-extractor';
import { EnsembleModelService, FraudScore } from '../models/ensemble-model';

/**
 * Fraud Decision
 */
export enum FraudDecision {
  APPROVE = 'approve',
  DECLINE = 'decline',
  REVIEW = 'review',
}

/**
 * Fraud Assessment Result
 */
export interface FraudAssessment {
  transactionId: string;
  decision: FraudDecision;
  score: number;
  confidence: number;
  latency: number;
  explanation: string[];
  modelContributions: {
    randomForest: number;
    neuralNetwork: number;
  };
  timestamp: Date;
}

/**
 * Fraud Scoring Service
 * 
 * Orchestrates the fraud detection pipeline:
 * 1. Feature extraction
 * 2. Model inference
 * 3. Decision making
 * 
 * Target: Sub-100ms latency
 */
@Injectable()
export class FraudScoringService {
  private readonly logger = new Logger(FraudScoringService.name);
  
  // Decision thresholds
  private readonly AUTO_DECLINE_THRESHOLD = 90;
  private readonly MANUAL_REVIEW_THRESHOLD = 50;

  constructor(
    private readonly featureExtractor: FeatureExtractor,
    private readonly ensembleModel: EnsembleModelService,
  ) {}

  /**
   * Score a transaction for fraud risk
   * Complete pipeline: feature extraction + model inference + decision
   */
  async scoreTransaction(
    transaction: Transaction,
    userProfile: UserProfile
  ): Promise<FraudAssessment> {
    const startTime = Date.now();

    try {
      // Step 1: Extract features
      const features = await this.featureExtractor.extractFeatures(
        transaction,
        userProfile
      );

      // Step 2: Run model prediction
      const fraudScore = await this.ensembleModel.predict(features);

      // Step 3: Make decision
      const decision = this.makeDecision(fraudScore.score);

      const latency = Date.now() - startTime;

      // Log if latency exceeds target
      if (latency > 100) {
        this.logger.warn(
          `Fraud scoring latency ${latency}ms exceeded target (100ms) for transaction ${transaction.id}`
        );
      }

      const assessment: FraudAssessment = {
        transactionId: transaction.id,
        decision,
        score: fraudScore.score,
        confidence: fraudScore.confidence,
        latency,
        explanation: fraudScore.explanation,
        modelContributions: fraudScore.modelContributions,
        timestamp: new Date(),
      };

      this.logger.debug(
        `Transaction ${transaction.id}: score=${assessment.score}, decision=${assessment.decision}, latency=${latency}ms`
      );

      return assessment;
    } catch (error) {
      this.logger.error(
        `Fraud scoring failed for transaction ${transaction.id}: ${error.message}`
      );

      // Return conservative decision on error
      return {
        transactionId: transaction.id,
        decision: FraudDecision.REVIEW,
        score: 50,
        confidence: 0,
        latency: Date.now() - startTime,
        explanation: ['Scoring failed - manual review required'],
        modelContributions: { randomForest: 50, neuralNetwork: 50 },
        timestamp: new Date(),
      };
    }
  }

  /**
   * Batch score multiple transactions
   */
  async scoreBatch(
    transactions: Array<{ transaction: Transaction; userProfile: UserProfile }>
  ): Promise<FraudAssessment[]> {
    // Process in parallel with concurrency limit
    const concurrencyLimit = 10;
    const results: FraudAssessment[] = [];

    for (let i = 0; i < transactions.length; i += concurrencyLimit) {
      const batch = transactions.slice(i, i + concurrencyLimit);
      const batchResults = await Promise.all(
        batch.map(({ transaction, userProfile }) =>
          this.scoreTransaction(transaction, userProfile)
        )
      );
      results.push(...batchResults);
    }

    return results;
  }

  /**
   * Make decision based on fraud score
   */
  private makeDecision(score: number): FraudDecision {
    if (score >= this.AUTO_DECLINE_THRESHOLD) {
      return FraudDecision.DECLINE;
    }
    
    if (score >= this.MANUAL_REVIEW_THRESHOLD) {
      return FraudDecision.REVIEW;
    }
    
    return FraudDecision.APPROVE;
  }

  /**
   * Get decision thresholds
   */
  getThresholds(): {
    autoDecline: number;
    manualReview: number;
  } {
    return {
      autoDecline: this.AUTO_DECLINE_THRESHOLD,
      manualReview: this.MANUAL_REVIEW_THRESHOLD,
    };
  }

  /**
   * Update decision thresholds (for adaptive thresholding)
   */
  updateThresholds(
    autoDecline: number,
    manualReview: number
  ): void {
    // Validation
    if (manualReview >= autoDecline) {
      throw new Error('Manual review threshold must be less than auto-decline threshold');
    }
    
    if (autoDecline > 100 || manualReview < 0) {
      throw new Error('Thresholds must be between 0 and 100');
    }

    // In a real implementation, these would be stored in a configuration service
    // For now, we just log the change
    this.logger.log(
      `Updated thresholds: auto-decline=${autoDecline}, manual-review=${manualReview}`
    );
  }

  /**
   * Get service health status
   */
  getHealthStatus(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    averageLatency: number;
    totalScored: number;
  } {
    // In production, this would track actual metrics
    return {
      status: 'healthy',
      averageLatency: 45, // Placeholder
      totalScored: 0, // Placeholder
    };
  }
}
