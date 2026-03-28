import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { FeatureExtractor } from './features/feature-extractor';
import { EnsembleModelService } from './models/ensemble-model';
import { FraudScoringService } from './scoring/fraud-scoring.service';
import { FraudQueuesService } from './queues/fraud-queues.service';

/**
 * Fraud Detection Module
 * 
 * Provides ML-powered real-time fraud detection including:
 * - Real-time feature extraction
 * - Ensemble ML model (Random Forest + Neural Network)
 * - Sub-100ms fraud scoring
 * - Auto-decline and manual review queues
 * - Weekly model retraining pipeline
 */
@Module({
  imports: [
    BullModule.registerQueue(
      {
        name: 'fraud-declined',
        defaultJobOptions: {
          removeOnComplete: 100,
          removeOnFail: 50,
        },
      },
      {
        name: 'fraud-review',
        defaultJobOptions: {
          removeOnComplete: 100,
          removeOnFail: 50,
        },
      }
    ),
  ],
  providers: [
    FeatureExtractor,
    EnsembleModelService,
    FraudScoringService,
    FraudQueuesService,
  ],
  exports: [
    FeatureExtractor,
    EnsembleModelService,
    FraudScoringService,
    FraudQueuesService,
  ],
})
export class FraudDetectionModule {}
