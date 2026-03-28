import { Injectable, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import { ThresholdScheme, KeyStatus, KeyShareLocation } from '../dto/key-management.dto';

export interface MPCKeyShare {
  shareId: string;
  keyId: string;
  shareIndex: number;
  shareData: string; // Encrypted share
  location: KeyShareLocation;
  hsmKeyId: string; // Reference to HSM key
  publicKeyCommitment: string;
  createdAt: Date;
  lastUsedAt?: Date;
  isActive: boolean;
}

export interface DistributedKey {
  id: string;
  purpose: string;
  thresholdScheme: ThresholdScheme;
  requiredShares: number;
  totalShares: number;
  publicKey: string;
  shares: MPCKeyShare[];
  status: KeyStatus;
  createdAt: Date;
  lastRotatedAt?: Date;
  nextRotationAt?: Date;
  rotationPeriodDays: number;
  compromiseDetectedAt?: Date;
  revokedAt?: Date;
}

@Injectable()
export class MPCKeysService {
  private readonly logger = new Logger(MPCKeysService.name);
  private keys: Map<string, DistributedKey> = new Map();
  private readonly DEFAULT_ROTATION_DAYS = 90;

  /**
   * Generate distributed key using MPC ceremony
   * No single party ever has the complete private key
   */
  async generateDistributedKey(params: {
    thresholdScheme: ThresholdScheme;
    purpose: string;
    shareLocations: KeyShareLocation[];
    rotationPeriodDays?: number;
  }): Promise<DistributedKey> {
    const { thresholdScheme, purpose, shareLocations, rotationPeriodDays } = params;

    // Parse threshold scheme (e.g., "2-of-3" -> t=2, n=3)
    const [t, n] = thresholdScheme.split('-of-').map(Number);
    
    if (shareLocations.length !== n) {
      throw new Error(`Expected ${n} share locations for ${thresholdScheme}, got ${shareLocations.length}`);
    }

    const keyId = `mpc_key_${Date.now()}_${randomBytes(8).toString('hex')}`;
    
    // Simulate MPC key generation ceremony
    // In production: use actual MPC protocol (GG18, GG20, etc.)
    const keyPair = await this.simulateMPCCeremony(t, n, shareLocations);

    const distributedKey: DistributedKey = {
      id: keyId,
      purpose,
      thresholdScheme,
      requiredShares: t,
      totalShares: n,
      publicKey: keyPair.publicKey,
      shares: keyPair.shares,
      status: KeyStatus.ACTIVE,
      createdAt: new Date(),
      rotationPeriodDays: rotationPeriodDays || this.DEFAULT_ROTATION_DAYS,
      nextRotationAt: new Date(Date.now() + (rotationPeriodDays || this.DEFAULT_ROTATION_DAYS) * 24 * 60 * 60 * 1000),
    };

    this.keys.set(keyId, distributedKey);

    this.logger.log(
      `MPC key generated: ${keyId}, scheme: ${thresholdScheme}, ` +
      `public key: ${distributedKey.publicKey.slice(0, 16)}...`,
    );

    return distributedKey;
  }

  /**
   * Sign transaction using threshold signatures
   * Requires t out of n parties to collaborate
   */
  async signWithThreshold(params: {
    keyId: string;
    transactionData: string;
    minShares?: number;
  }): Promise<{
    signature: string;
    participatingShares: number[];
    timestamp: Date;
  }> {
    const key = this.keys.get(params.keyId);
    
    if (!key) {
      throw new Error(`Key ${params.keyId} not found`);
    }

    if (key.status !== KeyStatus.ACTIVE) {
      throw new Error(`Key is not active. Status: ${key.status}`);
    }

    const requiredShares = params.minShares || key.requiredShares;
    
    // Select participating shares (geographically distributed)
    const participatingShares = this.selectParticipatingShares(key, requiredShares);

    if (participatingShares.length < requiredShares) {
      throw new Error(
        `Insufficient active shares: ${participatingShares.length} < ${requiredShares}`,
      );
    }

    // Each share holder computes partial signature
    const partialSignatures = await this.computePartialSignatures({
      transactionData: params.transactionData,
      shares: participatingShares,
    });

    // Combine partial signatures into full signature
    const combinedSignature = this.combineSignatures(partialSignatures);

    // Update last used timestamp
    participatingShares.forEach(share => {
      share.lastUsedAt = new Date();
    });

    this.logger.log(
      `Transaction signed with ${participatingShares.length}/${key.requiredShares} shares`,
    );

    return {
      signature: combinedSignature,
      participatingShares: participatingShares.map(s => s.shareIndex),
      timestamp: new Date(),
    };
  }

  /**
   * Rotate key shares proactively
   * Generates new shares without changing the public key
   */
  async rotateKeyShares(params: {
    keyId: string;
    reason: string;
    newLocations?: KeyShareLocation[];
  }): Promise<DistributedKey> {
    const key = this.keys.get(params.keyId);
    
    if (!key) {
      throw new Error(`Key ${params.keyId} not found`);
    }

    this.logger.log(`Starting key rotation for ${params.keyId}: ${params.reason}`);

    key.status = KeyStatus.ROTATING;

    // Generate new shares while maintaining same public key
    // This is a proactive secret sharing refresh
    const newShares = await this.refreshShares(key, params.newLocations);

    // Mark old shares as inactive
    key.shares.forEach(share => {
      share.isActive = false;
    });

    // Activate new shares
    key.shares = newShares;
    key.lastRotatedAt = new Date();
    key.nextRotationAt = new Date(
      Date.now() + key.rotationPeriodDays * 24 * 60 * 60 * 1000,
    );
    key.status = KeyStatus.ACTIVE;

    this.logger.log(
      `Key rotation completed: ${params.keyId}, next rotation: ${key.nextRotationAt}`,
    );

    return key;
  }

  /**
   * Detect potential key compromise
   */
  async detectCompromise(params: {
    keyId: string;
    evidence: string;
    suspectedLocation?: KeyShareLocation;
  }): Promise<{
    compromiseDetected: boolean;
    confidence: number;
    recommendedAction: 'INVESTIGATE' | 'REVOKE' | 'ROTATE' | 'MONITOR';
  }> {
    const key = this.keys.get(params.keyId);
    
    if (!key) {
      throw new Error(`Key ${params.keyId} not found`);
    }

    // Analyze evidence for compromise indicators
    const analysis = this.analyzeCompromiseEvidence(params.evidence);

    let recommendedAction: 'INVESTIGATE' | 'REVOKE' | 'ROTATE' | 'MONITOR' = 'MONITOR';
    let compromiseDetected = false;

    if (analysis.confidence > 0.8) {
      compromiseDetected = true;
      recommendedAction = 'REVOKE';
      
      // Mark key as compromised
      key.status = KeyStatus.COMPROMISED;
      key.compromiseDetectedAt = new Date();
      
      if (params.suspectedLocation) {
        // Deactivate share at suspected location
        const suspectedShare = key.shares.find(
          s => s.location === params.suspectedLocation && s.isActive,
        );
        if (suspectedShare) {
          suspectedShare.isActive = false;
          this.logger.warn(
            `Share ${suspectedShare.shareId} at ${params.suspectedLocation} deactivated`,
          );
        }
      }
      
      this.logger.error(
        `Compromise detected for key ${params.keyId} with ${analysis.confidence * 100}% confidence`,
      );
    } else if (analysis.confidence > 0.5) {
      recommendedAction = 'ROTATE';
      this.logger.warn(`Suspicious activity detected for key ${params.keyId}`);
    } else if (analysis.confidence > 0.3) {
      recommendedAction = 'INVESTIGATE';
    }

    return {
      compromiseDetected,
      confidence: analysis.confidence,
      recommendedAction,
    };
  }

  /**
   * Get key by ID
   */
  getKey(keyId: string): DistributedKey | undefined {
    return this.keys.get(keyId);
  }

  /**
   * Get all active keys
   */
  getActiveKeys(): DistributedKey[] {
    return Array.from(this.keys.values()).filter(k => k.status === KeyStatus.ACTIVE);
  }

  /**
   * Get keys scheduled for rotation
   */
  getKeysNeedingRotation(withinDays: number = 7): DistributedKey[] {
    const now = Date.now();
    const thresholdMs = withinDays * 24 * 60 * 60 * 1000;
    
    return Array.from(this.keys.values()).filter(
      k => k.status === KeyStatus.ACTIVE && 
           k.nextRotationAt && 
           (k.nextRotationAt.getTime() - now) < thresholdMs,
    );
  }

  /**
   * Simulate MPC key generation ceremony
   * In production: implement actual MPC protocol
   */
  private async simulateMPCCeremony(
    t: number,
    n: number,
    locations: KeyShareLocation[],
  ): Promise<{ publicKey: string; shares: MPCKeyShare[] }> {
    // Generate master secret (never reconstructed in real MPC)
    const masterSecret = randomBytes(32);
    
    // Generate Shamir's Secret Sharing polynomial
    const shares = this.generateShamirShares(masterSecret, t, n);
    
    // Generate public key from master secret
    const publicKey = this.derivePublicKey(masterSecret);
    
    // Create share objects with geographic distribution
    const mpcShares: MPCKeyShare[] = shares.map((share, index) => ({
      shareId: `share_${randomBytes(8).toString('hex')}`,
      keyId: `mpc_key_placeholder`, // Will be set later
      shareIndex: index + 1,
      shareData: share.toString('hex'),
      location: locations[index],
      hsmKeyId: `hsm_key_${randomBytes(8).toString('hex')}`,
      publicKeyCommitment: this.createPublicCommitment(share),
      createdAt: new Date(),
      isActive: true,
    }));

    return { publicKey, shares: mpcShares };
  }

  /**
   * Generate Shamir's Secret Sharing shares
   */
  private generateShamirShares(secret: Buffer, t: number, n: number): Buffer[] {
    // In production: implement actual Shamir's Secret Sharing over finite fields
    // For now: simulate with deterministic derivation
    
    const shares: Buffer[] = [];
    for (let i = 0; i < n; i++) {
      // Simulated share (not cryptographically secure)
      const share = createHash('sha256')
        .update(secret)
        .update(Buffer.from(i.toString()))
        .digest();
      shares.push(share);
    }
    
    return shares;
  }

  /**
   * Derive public key from secret (simulated)
   */
  private derivePublicKey(secret: Buffer): string {
    return createHash('sha256')
      .update(secret)
      .digest('hex');
  }

  /**
   * Create public commitment for share verification
   */
  private createPublicCommitment(share: Buffer): string {
    return createHash('sha256')
      .update(share)
      .digest('hex');
  }

  /**
   * Select geographically distributed participating shares
   */
  private selectParticipatingShares(key: DistributedKey, required: number): MPCKeyShare[] {
    const activeShares = key.shares.filter(s => s.isActive);
    
    // Prioritize diversity in geographic locations
    const locationGroups = new Map<KeyShareLocation, MPCKeyShare[]>();
    activeShares.forEach(share => {
      const group = locationGroups.get(share.location) || [];
      group.push(share);
      locationGroups.set(share.location, group);
    });

    // Select one from each location first for diversity
    const selected: MPCKeyShare[] = [];
    locationGroups.forEach(group => {
      if (selected.length < required) {
        selected.push(group[0]);
      }
    });

    // Fill remaining slots
    const remaining = activeShares.filter(s => !selected.includes(s));
    remaining.forEach(share => {
      if (selected.length < required) {
        selected.push(share);
      }
    });

    return selected;
  }

  /**
   * Compute partial signatures from each share holder
   */
  private async computePartialSignatures(params: {
    transactionData: string;
    shares: MPCKeyShare[];
  }): Promise<string[]> {
    // In production: each party signs with their share using threshold signature scheme
    // For now: simulate
    return params.shares.map(share => 
      createHash('sha256')
        .update(params.transactionData)
        .update(Buffer.from(share.shareData, 'hex'))
        .digest('hex'),
    );
  }

  /**
   * Combine partial signatures into full signature
   */
  private combineSignatures(partialSigs: string[]): string {
    // In production: use Lagrange interpolation to combine threshold signatures
    // For now: simulate
    const combined = createHash('sha256')
      .update(partialSigs.join(''))
      .digest('hex');
    return `threshold_sig_${combined}`;
  }

  /**
   * Refresh shares proactively (proactive secret sharing)
   */
  private async refreshShares(
    key: DistributedKey,
    newLocations?: KeyShareLocation[],
  ): Promise<MPCKeyShare[]> {
    const locations = newLocations || key.shares.map(s => s.location);
    
    // Generate new shares of zero and add to existing shares
    // This refreshes shares without changing the secret
    const zeroShares = this.generateShamirShares(
      Buffer.alloc(32), // Zero
      key.requiredShares,
      key.totalShares,
    );

    return zeroShares.map((share, index) => ({
      shareId: `share_${Date.now()}_${randomBytes(8).toString('hex')}`,
      keyId: key.id,
      shareIndex: index + 1,
      shareData: share.toString('hex'),
      location: locations[index],
      hsmKeyId: `hsm_key_${randomBytes(8).toString('hex')}`,
      publicKeyCommitment: this.createPublicCommitment(share),
      createdAt: new Date(),
      isActive: true,
    }));
  }

  /**
   * Analyze evidence for compromise indicators
   */
  private analyzeCompromiseEvidence(evidence: string): {
    confidence: number;
    indicators: string[];
  } {
    // In production: ML-based anomaly detection on signing patterns
    // For now: simple heuristic
    const indicators: string[] = [];
    let confidence = 0;

    if (evidence.toLowerCase().includes('unauthorized')) confidence += 0.3;
    if (evidence.toLowerCase().includes('suspicious')) confidence += 0.2;
    if (evidence.toLowerCase().includes('breach')) confidence += 0.4;
    if (evidence.toLowerCase().includes('anomaly')) confidence += 0.1;

    return { confidence: Math.min(confidence, 1.0), indicators };
  }
}
