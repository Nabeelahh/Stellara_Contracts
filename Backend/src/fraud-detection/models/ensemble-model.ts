import { Injectable, Logger } from '@nestjs/common';
import { FraudFeatures } from '../features/feature-extractor';

/**
 * Fraud Score Result
 */
export interface FraudScore {
  score: number; // 0-100
  confidence: number; // 0-1
  modelContributions: {
    randomForest: number;
    neuralNetwork: number;
  };
  featureImportance: Map<string, number>;
  explanation: string[];
  latency: number; // ms
}

/**
 * Model Prediction
 */
interface ModelPrediction {
  score: number;
  confidence: number;
  featureImportance: Map<string, number>;
}

/**
 * Ensemble Model Service
 * 
 * Combines Random Forest and Neural Network models for fraud detection.
 * Uses weighted averaging for final score.
 */
@Injectable()
export class EnsembleModelService {
  private readonly logger = new Logger(EnsembleModelService.name);
  
  // Model weights for ensemble
  private readonly RF_WEIGHT = 0.6;
  private readonly NN_WEIGHT = 0.4;
  
  // Thresholds
  private readonly HIGH_RISK_THRESHOLD = 90;
  private readonly MEDIUM_RISK_THRESHOLD = 50;

  constructor() {}

  /**
   * Predict fraud score using ensemble of models
   * Target: Sub-100ms latency
   */
  async predict(features: FraudFeatures): Promise<FraudScore> {
    const startTime = Date.now();

    try {
      // Run both models in parallel
      const [rfPrediction, nnPrediction] = await Promise.all([
        this.randomForestPredict(features),
        this.neuralNetworkPredict(features),
      ]);

      // Combine predictions using weighted average
      const ensembleScore = this.combinePredictions(
        rfPrediction,
        nnPrediction
      );

      // Calculate combined confidence
      const confidence = this.calculateConfidence(
        rfPrediction.confidence,
        nnPrediction.confidence
      );

      // Merge feature importance
      const featureImportance = this.mergeFeatureImportance(
        rfPrediction.featureImportance,
        nnPrediction.featureImportance
      );

      // Generate explanation
      const explanation = this.generateExplanation(
        features,
        ensembleScore,
        featureImportance
      );

      const latency = Date.now() - startTime;

      this.logger.debug(`Fraud prediction completed in ${latency}ms`);

      return {
        score: ensembleScore,
        confidence,
        modelContributions: {
          randomForest: rfPrediction.score,
          neuralNetwork: nnPrediction.score,
        },
        featureImportance,
        explanation,
        latency,
      };
    } catch (error) {
      this.logger.error(`Fraud prediction failed: ${error.message}`);
      
      // Return conservative score on error
      return {
        score: 50,
        confidence: 0,
        modelContributions: { randomForest: 50, neuralNetwork: 50 },
        featureImportance: new Map(),
        explanation: ['Prediction failed - manual review required'],
        latency: Date.now() - startTime,
      };
    }
  }

  /**
   * Random Forest prediction
   * Simulated implementation - in production, use actual ML model
   */
  private async randomForestPredict(
    features: FraudFeatures
  ): Promise<ModelPrediction> {
    // Simulate model inference
    // In production, this would call a trained Random Forest model
    
    const featureVector = this.featuresToVector(features);
    
    // Simulate tree-based scoring
    let score = 0;
    const importance = new Map<string, number>();

    // Amount-based rules (high amounts = higher risk)
    if (features.amount > 10000) {
      score += 20;
      importance.set('amount', 0.15);
    }

    // Velocity checks
    if (features.transactionsLastHour > 5) {
      score += 25;
      importance.set('transactionsLastHour', 0.2);
    }

    // Device risk
    if (features.isNewDevice) {
      score += 15;
      importance.set('isNewDevice', 0.1);
    }

    // Location risk
    if (features.isHighRiskCountry) {
      score += 30;
      importance.set('isHighRiskCountry', 0.15);
    }

    if (features.isNewLocation) {
      score += 10;
      importance.set('isNewLocation', 0.05);
    }

    // Network risk
    if (features.isVpn || features.isTor || features.isProxy) {
      score += 20;
      importance.set('networkAnonymity', 0.1);
    }

    // User history
    if (features.userChargebackRate > 0.05) {
      score += 25;
      importance.set('userChargebackRate', 0.15);
    }

    // Time-based patterns
    if (!features.isBusinessHours && features.amount > 5000) {
      score += 10;
      importance.set('timePattern', 0.05);
    }

    // Normalize score to 0-100
    score = Math.min(100, Math.max(0, score));

    // Calculate confidence based on feature coverage
    const confidence = this.calculateModelConfidence(featureVector);

    return {
      score,
      confidence,
      featureImportance: importance,
    };
  }

  /**
   * Neural Network prediction
   * Simulated implementation - in production, use actual ML model
   */
  private async neuralNetworkPredict(
    features: FraudFeatures
  ): Promise<ModelPrediction> {
    // Simulate neural network inference
    // In production, this would call a trained NN model (TensorFlow, PyTorch, etc.)
    
    const featureVector = this.featuresToVector(features);
    
    // Simulate deep learning pattern recognition
    let score = 0;
    const importance = new Map<string, number>();

    // Pattern-based scoring (simulating learned patterns)
    const patterns = this.detectPatterns(features);
    
    for (const pattern of patterns) {
      score += pattern.riskContribution;
      importance.set(pattern.name, pattern.importance);
    }

    // Behavioral anomaly detection
    const behavioralScore = this.analyzeBehavioralPatterns(features);
    score += behavioralScore.score;
    
    for (const [feature, imp] of behavioralScore.importance) {
      const current = importance.get(feature) || 0;
      importance.set(feature, current + imp);
    }

    // Normalize score
    score = Math.min(100, Math.max(0, score));

    // NN typically has higher confidence with more data
    const confidence = Math.min(0.95, 0.7 + (features.userTotalTransactions / 1000));

    return {
      score,
      confidence,
      featureImportance: importance,
    };
  }

  /**
   * Combine predictions from both models
   */
  private combinePredictions(
    rf: ModelPrediction,
    nn: ModelPrediction
  ): number {
    // Weighted average
    const weightedScore =
      rf.score * this.RF_WEIGHT +
      nn.score * this.NN_WEIGHT;

    return Math.round(weightedScore);
  }

  /**
   * Calculate combined confidence
   */
  private calculateConfidence(rfConf: number, nnConf: number): number {
    // Average confidence, weighted by model reliability
    return (rfConf * this.RF_WEIGHT + nnConf * this.NN_WEIGHT);
  }

  /**
   * Merge feature importance from both models
   */
  private mergeFeatureImportance(
    rf: Map<string, number>,
    nn: Map<string, number>
  ): Map<string, number> {
    const merged = new Map<string, number>();

    // Merge RF importance
    for (const [feature, importance] of rf) {
      merged.set(feature, importance * this.RF_WEIGHT);
    }

    // Merge NN importance
    for (const [feature, importance] of nn) {
      const current = merged.get(feature) || 0;
      merged.set(feature, current + importance * this.NN_WEIGHT);
    }

    // Normalize
    const total = Array.from(merged.values()).reduce((a, b) => a + b, 0);
    if (total > 0) {
      for (const [feature, importance] of merged) {
        merged.set(feature, importance / total);
      }
    }

    return merged;
  }

  /**
   * Generate human-readable explanation
   */
  private generateExplanation(
    features: FraudFeatures,
    score: number,
    importance: Map<string, number>
  ): string[] {
    const explanations: string[] = [];

    // Sort features by importance
    const sortedFeatures = Array.from(importance.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    for (const [feature, imp] of sortedFeatures) {
      if (imp > 0.05) {
        explanations.push(this.explainFeature(feature, features));
      }
    }

    // Add overall risk assessment
    if (score >= this.HIGH_RISK_THRESHOLD) {
      explanations.push(`High risk score (${score}) - automatic decline recommended`);
    } else if (score >= this.MEDIUM_RISK_THRESHOLD) {
      explanations.push(`Medium risk score (${score}) - manual review recommended`);
    }

    return explanations;
  }

  /**
   * Explain a specific feature contribution
   */
  private explainFeature(feature: string, features: FraudFeatures): string {
    const explanations: Record<string, string> = {
      amount: `Transaction amount $${features.amount} is ${features.amountDeviationFromAverage > 0 ? 'above' : 'below'} user average`,
      transactionsLastHour: `${features.transactionsLastHour} transactions in the last hour`,
      isNewDevice: 'Transaction from a new device',
      isHighRiskCountry: 'Transaction from a high-risk country',
      isNewLocation: 'Transaction from a new location',
      networkAnonymity: 'Use of VPN/Tor/Proxy detected',
      userChargebackRate: `User has ${(features.userChargebackRate * 100).toFixed(1)}% chargeback rate`,
    };

    return explanations[feature] || `${feature} contributed to risk score`;
  }

  /**
   * Convert features to vector for model input
   */
  private featuresToVector(features: FraudFeatures): number[] {
    return [
      features.amount,
      features.amountDeviationFromAverage,
      features.timeSinceLastTransaction,
      features.transactionsLastHour,
      features.transactionsLastDay,
      features.amountVelocityHourly,
      features.deviceRiskScore,
      features.locationRiskScore,
      features.ipRiskScore,
      features.userAccountAge,
      features.userTotalTransactions,
      features.userChargebackRate,
      features.isNewDevice ? 1 : 0,
      features.isNewLocation ? 1 : 0,
      features.isHighRiskCountry ? 1 : 0,
      features.isVpn ? 1 : 0,
      features.isTor ? 1 : 0,
      features.isProxy ? 1 : 0,
    ];
  }

  /**
   * Calculate model confidence based on feature coverage
   */
  private calculateModelConfidence(featureVector: number[]): number {
    const nonZeroFeatures = featureVector.filter(v => v !== 0).length;
    return Math.min(0.95, nonZeroFeatures / featureVector.length);
  }

  /**
   * Detect patterns (simulated for NN)
   */
  private detectPatterns(features: FraudFeatures): Array<{
    name: string;
    riskContribution: number;
    importance: number;
  }> {
    const patterns: Array<{
      name: string;
      riskContribution: number;
      importance: number;
    }> = [];

    // Velocity burst pattern
    if (features.transactionsLastHour > 3 && features.amount > 1000) {
      patterns.push({
        name: 'velocity_burst',
        riskContribution: 15,
        importance: 0.15,
      });
    }

    // Unusual time pattern
    if (!features.isBusinessHours && features.isNewDevice) {
      patterns.push({
        name: 'unusual_time_device',
        riskContribution: 10,
        importance: 0.1,
      });
    }

    // High value + new location
    if (features.amount > 5000 && features.isNewLocation) {
      patterns.push({
        name: 'high_value_new_location',
        riskContribution: 20,
        importance: 0.2,
      });
    }

    return patterns;
  }

  /**
   * Analyze behavioral patterns
   */
  private analyzeBehavioralPatterns(features: FraudFeatures): {
    score: number;
    importance: Map<string, number>;
  } {
    let score = 0;
    const importance = new Map<string, number>();

    // Account age vs transaction volume anomaly
    if (features.userAccountAge < 7 && features.amount > 1000) {
      score += 15;
      importance.set('account_age_volume', 0.1);
    }

    // Distance anomaly
    if (features.distanceFromTypicalLocation > 500) {
      score += 10;
      importance.set('distance_anomaly', 0.08);
    }

    return { score, importance };
  }
}
