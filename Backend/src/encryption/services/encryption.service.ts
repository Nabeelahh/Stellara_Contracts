import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

export interface EncryptionResult {
  encryptedData: string;
  iv: string;
  keyId: string;
  algorithm: string;
}

export interface DecryptionResult {
  decryptedData: string;
  success: boolean;
  error?: string;
}

export interface EncryptionKey {
  id: string;
  keyData: string;
  algorithm: string;
  keySize: number;
  createdAt: Date;
  expiresAt: Date;
  isRevoked: boolean;
  lastUsedAt?: Date;
}

export interface EncryptionAuditLog {
  id: string;
  keyId: string;
  userId?: string;
  action: 'ENCRYPT' | 'DECRYPT' | 'KEY_ROTATE' | 'KEY_REVOKE';
  field?: string;
  table?: string;
  timestamp: Date;
  ipAddress: string;
  userAgent?: string;
  success: boolean;
  error?: string;
}

@Injectable()
export class EncryptionService {
  private readonly logger = new Logger(EncryptionService.name);
  private readonly algorithm = 'aes-256-gcm';
  private readonly keySize = 32; // 256 bits
  private readonly ivSize = 16; // 128 bits
  private readonly tagSize = 16; // 128 bits
  private readonly keyRotationInterval = 90 * 24 * 60 * 60 * 1000; // 90 days in ms
  private encryptionKeys: Map<string, EncryptionKey> = new Map();
  private auditLogs: EncryptionAuditLog[] = [];

  constructor(private readonly configService: ConfigService) {
    this.initializeEncryption();
  }

  private async initializeEncryption(): Promise<void> {
    // Initialize master key from environment
    const masterKey = this.configService.get<string>('ENCRYPTION_MASTER_KEY');
    if (!masterKey) {
      throw new Error('ENCRYPTION_MASTER_KEY environment variable is required');
    }

    // Generate initial encryption key
    await this.generateInitialKey();

    // Start key rotation scheduler
    this.scheduleKeyRotation();
  }

  private async generateInitialKey(): Promise<void> {
    const keyId = this.generateKeyId();
    const keyData = this.generateEncryptionKey();

    const encryptionKey: EncryptionKey = {
      id: keyId,
      keyData,
      algorithm: this.algorithm,
      keySize: this.keySize * 8, // in bits
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.keyRotationInterval),
      isRevoked: false,
    };

    this.encryptionKeys.set(keyId, encryptionKey);
    this.logger.log(`Generated initial encryption key: ${keyId}`);
  }

  async encryptField(data: string, fieldType: string): Promise<EncryptionResult> {
    const startTime = Date.now();
    let keyId: string;
    let success = false;
    let error: string | undefined;

    try {
      // Get current active key
      const activeKey = this.getActiveKey();
      keyId = activeKey.id;

      // Generate IV for this encryption
      const iv = crypto.randomBytes(this.ivSize);

      // Create cipher
      const cipher = crypto.createCipher(this.algorithm, activeKey.keyData);

      // Encrypt the data
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const result: EncryptionResult = {
        encryptedData: encrypted,
        iv: iv.toString('hex'),
        keyId,
        algorithm: this.algorithm,
      };

      success = true;

      // Update key usage
      activeKey.lastUsedAt = new Date();

      // Log audit trail
      await this.logEncryptionActivity({
        keyId,
        action: 'ENCRYPT',
        field: fieldType,
        success: true,
        processingTime: Date.now() - startTime,
      });

      return result;
    } catch (err) {
      error = err.message;
      success = false;

      await this.logEncryptionActivity({
        keyId,
        action: 'ENCRYPT',
        field: fieldType,
        success: false,
        error: err.message,
        processingTime: Date.now() - startTime,
      });

      throw new Error(`Encryption failed: ${err.message}`);
    }
  }

  async decryptField(
    encryptedData: string,
    iv: string,
    keyId: string,
    fieldType: string,
  ): Promise<DecryptionResult> {
    const startTime = Date.now();
    let success = false;
    let error: string | undefined;

    try {
      // Get the key
      const key = this.encryptionKeys.get(keyId);
      if (!key || key.isRevoked) {
        throw new Error(`Invalid or revoked key: ${keyId}`);
      }

      // Create decipher
      const decipher = crypto.createDecipher(this.algorithm, key.keyData);

      // Decrypt the data
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      success = true;

      // Update key usage
      key.lastUsedAt = new Date();

      // Log audit trail
      await this.logEncryptionActivity({
        keyId,
        action: 'DECRYPT',
        field: fieldType,
        success: true,
        processingTime: Date.now() - startTime,
      });

      return {
        decryptedData: decrypted,
        success,
      };
    } catch (err) {
      error = err.message;
      success = false;

      await this.logEncryptionActivity({
        keyId,
        action: 'DECRYPT',
        field: fieldType,
        success: false,
        error: err.message,
        processingTime: Date.now() - startTime,
      });

      return {
        decryptedData: '',
        success,
        error: err.message,
      };
    }
  }

  async rotateKeys(): Promise<EncryptionKey> {
    this.logger.log('Starting key rotation...');

    const startTime = Date.now();
    let success = false;
    let error: string | undefined;

    try {
      // Generate new key
      const newKeyId = this.generateKeyId();
      const newKeyData = this.generateEncryptionKey();

      // Revoke old key
      const oldKey = this.getActiveKey();
      if (oldKey) {
        oldKey.isRevoked = true;
        oldKey.expiresAt = new Date(); // Immediate expiration
      }

      // Create new key
      const newKey: EncryptionKey = {
        id: newKeyId,
        keyData: newKeyData,
        algorithm: this.algorithm,
        keySize: this.keySize * 8,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + this.keyRotationInterval),
        isRevoked: false,
      };

      this.encryptionKeys.set(newKeyId, newKey);

      success = true;

      await this.logEncryptionActivity({
        keyId: newKeyId,
        action: 'KEY_ROTATE',
        success: true,
        processingTime: Date.now() - startTime,
      });

      this.logger.log(`Key rotation completed. New key: ${newKeyId}`);
      return newKey;
    } catch (err) {
      error = err.message;
      success = false;

      await this.logEncryptionActivity({
        keyId: 'unknown',
        action: 'KEY_ROTATE',
        success: false,
        error: err.message,
        processingTime: Date.now() - startTime,
      });

      throw new Error(`Key rotation failed: ${err.message}`);
    }
  }

  async revokeKey(keyId: string): Promise<boolean> {
    try {
      const key = this.encryptionKeys.get(keyId);
      if (!key) {
        return false;
      }

      key.isRevoked = true;
      key.expiresAt = new Date();

      await this.logEncryptionActivity({
        keyId,
        action: 'KEY_REVOKE',
        success: true,
      });

      this.logger.log(`Key revoked: ${keyId}`);
      return true;
    } catch (err) {
      this.logger.error(`Failed to revoke key ${keyId}:`, err);
      return false;
    }
  }

  getActiveKey(): EncryptionKey {
    const now = new Date();

    for (const key of this.encryptionKeys.values()) {
      if (!key.isRevoked && key.expiresAt > now) {
        return key;
      }
    }

    throw new Error('No active encryption key available');
  }

  getKeyById(keyId: string): EncryptionKey | null {
    return this.encryptionKeys.get(keyId) || null;
  }

  getAllKeys(): EncryptionKey[] {
    return Array.from(this.encryptionKeys.values());
  }

  getKeyRotationSchedule(): {
    nextRotation: Date;
    lastRotation: Date;
    interval: number;
  } {
    const activeKey = this.getActiveKey();
    return {
      nextRotation: activeKey.expiresAt,
      lastRotation: activeKey.createdAt,
      interval: this.keyRotationInterval,
    };
  }

  getEncryptionStatus(): {
    totalKeys: number;
    activeKeys: number;
    revokedKeys: number;
    oldestKey: Date | null;
    newestKey: Date | null;
  } {
    const now = new Date();
    const keys = Array.from(this.encryptionKeys.values());

    const activeKeys = keys.filter((key) => !key.isRevoked && key.expiresAt > now).length;
    const revokedKeys = keys.filter((key) => key.isRevoked).length;

    const dates = keys.map((key) => key.createdAt);
    const oldestKey = dates.length > 0 ? new Date(Math.min(...dates)) : null;
    const newestKey = dates.length > 0 ? new Date(Math.max(...dates)) : null;

    return {
      totalKeys: keys.length,
      activeKeys,
      revokedKeys,
      oldestKey,
      newestKey,
    };
  }

  getAuditLogs(limit: number = 100): EncryptionAuditLog[] {
    return this.auditLogs
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  private generateKeyId(): string {
    return `key_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  private generateEncryptionKey(): string {
    return crypto.randomBytes(this.keySize).toString('hex');
  }

  private async logEncryptionActivity(activity: Partial<EncryptionAuditLog>): Promise<void> {
    const logEntry: EncryptionAuditLog = {
      id: crypto.randomUUID(),
      keyId: activity.keyId || '',
      userId: activity.userId,
      action: activity.action!,
      field: activity.field,
      table: activity.table,
      timestamp: new Date(),
      ipAddress: '127.0.0.1', // In production, get from request
      userAgent: activity.userAgent,
      success: activity.success || false,
      error: activity.error,
      processingTime: activity.processingTime,
    };

    this.auditLogs.push(logEntry);

    // In production, save to database
    // await this.prisma.encryptionAuditLog.create({ data: logEntry });

    this.logger.debug(
      `Encryption audit: ${activity.action} - ${activity.success ? 'SUCCESS' : 'FAILED'}`,
    );
  }

  private scheduleKeyRotation(): void {
    // Schedule key rotation check every hour
    setInterval(
      async () => {
        try {
          const activeKey = this.getActiveKey();
          const now = new Date();

          // Rotate if key expires within next 24 hours
          if (activeKey.expiresAt.getTime() - now.getTime() <= 24 * 60 * 60 * 1000) {
            await this.rotateKeys();
          }
        } catch (error) {
          this.logger.error('Key rotation check failed:', error);
        }
      },
      60 * 60 * 1000,
    ); // Every hour
  }

  // Utility methods for common field types
  async encryptEmail(email: string): Promise<EncryptionResult> {
    return this.encryptField(email, 'email');
  }

  async encryptPhone(phone: string): Promise<EncryptionResult> {
    return this.encryptField(phone, 'phone');
  }

  async encryptSSN(ssn: string): Promise<EncryptionResult> {
    return this.encryptField(ssn, 'ssn');
  }

  async encryptCreditCard(cardNumber: string): Promise<EncryptionResult> {
    return this.encryptField(cardNumber, 'credit_card');
  }

  async encryptPersonalInfo(data: any): Promise<EncryptionResult> {
    const jsonData = JSON.stringify(data);
    return this.encryptField(jsonData, 'personal_info');
  }

  async encryptFinancialData(data: any): Promise<EncryptionResult> {
    const jsonData = JSON.stringify(data);
    return this.encryptField(jsonData, 'financial_data');
  }

  // Compliance methods
  async validateEncryptionCompliance(): Promise<{
    isCompliant: boolean;
    issues: string[];
    recommendations: string[];
  }> {
    const issues: string[] = [];
    const recommendations: string[] = [];

    const status = this.getEncryptionStatus();

    // Check for active keys
    if (status.activeKeys === 0) {
      issues.push('No active encryption keys available');
      recommendations.push('Generate a new encryption key immediately');
    }

    // Check for expired keys
    const now = new Date();
    const expiredKeys = Array.from(this.encryptionKeys.values()).filter(
      (key) => !key.isRevoked && key.expiresAt <= now,
    );

    if (expiredKeys.length > 0) {
      issues.push(`${expiredKeys.length} expired keys found`);
      recommendations.push('Rotate expired keys immediately');
    }

    // Check key rotation schedule
    const activeKey = this.getActiveKey();
    const timeToExpiration = activeKey.expiresAt.getTime() - now.getTime();
    const daysToExpiration = timeToExpiration / (24 * 60 * 60 * 1000);

    if (daysToExpiration < 7) {
      issues.push(`Key expires in ${Math.ceil(daysToExpiration)} days`);
      recommendations.push('Schedule key rotation');
    }

    return {
      isCompliant: issues.length === 0,
      issues,
      recommendations,
    };
  }
}
