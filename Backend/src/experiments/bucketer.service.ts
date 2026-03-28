import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class BucketerService {
  /**
   * Assigns a user to a bucket (0-99) consistently based on a key and user ID.
   */
  getBucket(experimentKey: string, userId: string): number {
    const hash = crypto
      .createHash('sha256')
      .update(`${experimentKey}:${userId}`)
      .digest('hex');
    
    // Take the first 8 characters and convert to an integer
    const intValue = parseInt(hash.substring(0, 8), 16);
    return intValue % 100;
  }

  /**
   * Determines if a user falls within a specific rollout percentage.
   */
  isInRollout(experimentKey: string, userId: string, rolloutPercentage: number): boolean {
    if (rolloutPercentage >= 100) return true;
    if (rolloutPercentage <= 0) return false;
    
    const bucket = this.getBucket(experimentKey, userId);
    return bucket < rolloutPercentage;
  }

  /**
   * Determines the variant for a user in an experiment.
   */
  getVariant(experimentKey: string, userId: string, controlSize: number): 'CONTROL' | 'TREATMENT' {
    const bucket = this.getBucket(`variant:${experimentKey}`, userId);
    return bucket < controlSize ? 'CONTROL' : 'TREATMENT';
  }
}
