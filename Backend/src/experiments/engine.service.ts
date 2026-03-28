import { Injectable } from '@nestjs/common';

export interface ExperimentStats {
  controlCount: number;
  controlConversions: number;
  treatmentCount: number;
  treatmentConversions: number;
}

export interface StatisticalResult {
  controlRate: number;
  treatmentRate: number;
  lift: number;
  zScore: number;
  pValue: number;
  isSignificant: boolean;
  confidenceInterval: [number, number];
}

@Injectable()
export class StatisticsEngineService {
  /**
   * Calculates the z-score and p-value for a two-proportions z-test.
   * Null hypothesis: control rate = treatment rate.
   */
  calculateSignificance(stats: ExperimentStats, confidenceLevel = 0.95): StatisticalResult {
    const {
      controlCount: n1,
      controlConversions: x1,
      treatmentCount: n2,
      treatmentConversions: x2,
    } = stats;

    if (n1 === 0 || n2 === 0) {
      return this.emptyResult();
    }

    const p1 = x1 / n1; // control conversion rate
    const p2 = x2 / n2; // treatment conversion rate
    const lift = p1 === 0 ? 0 : (p2 - p1) / p1;

    // Pooled probability
    const p_pooled = (x1 + x2) / (n1 + n2);
    
    // Standard error
    const se = Math.sqrt(p_pooled * (1 - p_pooled) * (1 / n1 + 1 / n2));

    if (se === 0) return this.emptyResult(p1, p2, lift);

    // Z-score
    const zScore = (p2 - p1) / se;

    // Two-tailed p-value (approximate using ERF)
    const pValue = this.zToP(zScore);

    // Is it significant?
    const alpha = 1 - confidenceLevel;
    const isSignificant = pValue < alpha;

    // Confidence Interval (95% approx ± 1.96 * SE)
    // Here we use SE for the difference (p2 - p1) NOT using pooled probability
    const se_diff = Math.sqrt((p1 * (1 - p1)) / n1 + (p2 * (1 - p2)) / n2);
    const z_alpha_half = 1.96; // for 95%
    const marginOfError = z_alpha_half * se_diff;

    return {
      controlRate: p1,
      treatmentRate: p2,
      lift,
      zScore,
      pValue,
      isSignificant,
      confidenceInterval: [p2 - p1 - marginOfError, p2 - p1 + marginOfError],
    };
  }

  /**
   * Approximate Normal CDF for z-score (two-tailed p-value)
   */
  private zToP(z: number): number {
    const absZ = Math.abs(z);
    // Standard approximation for normal distribution
    const t = 1 / (1 + 0.2316419 * absZ);
    const d = 0.3989423 * Math.exp((-absZ * absZ) / 2);
    const probs = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    
    // This is the area of the tail, we want two-tailed
    return 2 * probs;
  }

  private emptyResult(p1 = 0, p2 = 0, lift = 0): StatisticalResult {
    return {
      controlRate: p1,
      treatmentRate: p2,
      lift,
      zScore: 0,
      pValue: 1,
      isSignificant: false,
      confidenceInterval: [0, 0],
    };
  }
}
