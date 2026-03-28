import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class HtlcService {
  /**
   * Generates a random preimage (secret)
   */
  generatePreimage(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Computes the SHA-256 hash of a preimage (hash lock)
   */
  computeHash(preimage: string): string {
    return crypto.createHash('sha256').update(preimage, 'hex').digest('hex');
  }

  /**
   * Verifies if a preimage matches a hash lock
   */
  verify(preimage: string, hashLock: string): boolean {
    const computed = this.computeHash(preimage);
    return computed === hashLock;
  }
}
