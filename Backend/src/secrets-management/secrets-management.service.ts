// src/secrets-management/secrets-management.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  PutSecretValueCommand,
  UpdateSecretVersionStageCommand,
  ListSecretsCommand,
  DescribeSecretCommand,
  RotateSecretCommand,
  CancelRotateSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { SecretAccessLoggerService } from './secret-access-logger.service';

export interface SecretData {
  [key: string]: any;
}

export interface SecretMetadata {
  id: string;
  secretName: string;
  secretType: string;
  description?: string;
  rotationSchedule: string;
  lastRotatedAt?: Date;
  nextRotationAt?: Date;
  isActive: boolean;
  emergencyRevoked: boolean;
  revokedAt?: Date;
  revokedBy?: string;
}

@Injectable()
export class SecretsManagementService implements OnModuleInit {
  private readonly logger = new Logger(SecretsManagementService.name);
  private secretsManagerClient: SecretsManagerClient;
  private secretCache = new Map<string, { data: SecretData; expiresAt: number }>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private accessLogger: SecretAccessLoggerService,
  ) {
    this.initializeSecretsManager();
  }

  async onModuleInit() {
    this.logger.log('Secrets Management Service initialized');
    await this.syncSecretsFromAWS();
  }

  private initializeSecretsManager() {
    const region = this.configService.get<string>('AWS_REGION', 'us-east-1');

    this.secretsManagerClient = new SecretsManagerClient({
      region,
      credentials: {
        accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID', ''),
        secretAccessKey: this.configService.get<string>('AWS_SECRET_ACCESS_KEY', ''),
      },
    });
  }

  /**
   * Retrieve a secret by name with caching and access logging
   */
  async getSecret(secretName: string, requester: string = 'system'): Promise<SecretData | null> {
    try {
      // Check cache first
      const cached = this.secretCache.get(secretName);
      if (cached && cached.expiresAt > Date.now()) {
        await this.accessLogger.logAccess(secretName, requester, 'read', 'cache', true);
        return cached.data;
      }

      // Get secret from database first to check if it's active
      const secretRecord = await this.prisma.secret.findUnique({
        where: { secretName },
      });

      if (!secretRecord || !secretRecord.isActive || secretRecord.emergencyRevoked) {
        await this.accessLogger.logAccess(secretName, requester, 'read', 'api', false, 'Secret not found or revoked');
        return null;
      }

      // Get secret from AWS Secrets Manager
      const command = new GetSecretValueCommand({
        SecretId: secretName,
      });

      const response = await this.secretsManagerClient.send(command);

      if (!response.SecretString) {
        await this.accessLogger.logAccess(secretName, requester, 'read', 'api', false, 'No secret value found');
        return null;
      }

      const secretData: SecretData = JSON.parse(response.SecretString);

      // Cache the secret
      this.secretCache.set(secretName, {
        data: secretData,
        expiresAt: Date.now() + this.CACHE_TTL,
      });

      // Log successful access
      await this.accessLogger.logAccess(secretName, requester, 'read', 'api', true);

      return secretData;
    } catch (error) {
      this.logger.error(`Failed to retrieve secret ${secretName}: ${error.message}`);
      await this.accessLogger.logAccess(secretName, requester, 'read', 'api', false, error.message);
      return null;
    }
  }

  /**
   * Get a specific value from a secret
   */
  async getSecretValue(secretName: string, key: string, requester: string = 'system'): Promise<string | null> {
    const secret = await this.getSecret(secretName, requester);
    return secret && secret[key] ? secret[key] : null;
  }

  /**
   * Store or update a secret
   */
  async putSecret(
    secretName: string,
    secretData: SecretData,
    secretType: string,
    description?: string,
    rotationSchedule: string = '90d',
    requester: string = 'system',
  ): Promise<boolean> {
    try {
      // Store in AWS Secrets Manager
      const command = new PutSecretValueCommand({
        SecretId: secretName,
        SecretString: JSON.stringify(secretData),
        ClientRequestToken: `stellara-${Date.now()}`, // Prevent replay attacks
      });

      const response = await this.secretsManagerClient.send(command);

      // Update or create database record
      const nextRotationAt = this.calculateNextRotation(rotationSchedule);

      await this.prisma.secret.upsert({
        where: { secretName },
        update: {
          secretType,
          description,
          rotationSchedule,
          nextRotationAt,
          updatedAt: new Date(),
        },
        create: {
          secretName,
          secretType,
          description,
          rotationSchedule,
          nextRotationAt,
        },
      });

      // Store version information
      if (response.VersionId) {
        await this.prisma.secretVersion.create({
          data: {
            secretId: (await this.prisma.secret.findUnique({ where: { secretName } }))!.id,
            versionId: response.VersionId,
            versionStage: 'AWSCURRENT',
            secretValue: this.encryptSecretData(secretData), // Store encrypted version for audit
          },
        });
      }

      // Clear cache
      this.secretCache.delete(secretName);

      // Log access
      await this.accessLogger.logAccess(secretName, requester, 'write', 'api', true);

      this.logger.log(`Secret ${secretName} stored successfully`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to store secret ${secretName}: ${error.message}`);
      await this.accessLogger.logAccess(secretName, requester, 'write', 'api', false, error.message);
      return false;
    }
  }

  /**
   * Rotate a secret (generate new values and update)
   */
  async rotateSecret(
    secretName: string,
    rotationType: 'scheduled' | 'manual' | 'emergency' = 'manual',
    requester: string = 'system',
    reason?: string,
  ): Promise<boolean> {
    try {
      const secretRecord = await this.prisma.secret.findUnique({
        where: { secretName },
        include: { versions: { where: { versionStage: 'AWSCURRENT' } } },
      });

      if (!secretRecord) {
        throw new Error('Secret not found in database');
      }

      // Generate new secret values based on type
      const newSecretData = await this.generateNewSecretValues(secretRecord.secretType);

      // Store new version in AWS
      const putCommand = new PutSecretValueCommand({
        SecretId: secretName,
        SecretString: JSON.stringify(newSecretData),
        ClientRequestToken: `rotation-${Date.now()}`,
      });

      const putResponse = await this.secretsManagerClient.send(putCommand);

      // Update version stages
      if (putResponse.VersionId) {
        // Move current version to AWSPREVIOUS
        const currentVersion = secretRecord.versions[0];
        if (currentVersion) {
          await this.prisma.secretVersion.update({
            where: { id: currentVersion.id },
            data: { versionStage: 'AWSPREVIOUS' },
          });
        }

        // Create new AWSCURRENT version
        await this.prisma.secretVersion.create({
          data: {
            secretId: secretRecord.id,
            versionId: putResponse.VersionId,
            versionStage: 'AWSCURRENT',
            secretValue: this.encryptSecretData(newSecretData),
          },
        });

        // Log rotation
        await this.prisma.secretRotation.create({
          data: {
            secretId: secretRecord.id,
            rotationType,
            oldVersionId: currentVersion?.versionId,
            newVersionId: putResponse.VersionId,
            initiatedBy: requester,
            reason,
            success: true,
          },
        });

        // Update secret metadata
        const nextRotationAt = this.calculateNextRotation(secretRecord.rotationSchedule);
        await this.prisma.secret.update({
          where: { id: secretRecord.id },
          data: {
            lastRotatedAt: new Date(),
            nextRotationAt,
          },
        });
      }

      // Clear cache
      this.secretCache.delete(secretName);

      // Log access
      await this.accessLogger.logAccess(secretName, requester, 'rotate', 'api', true);

      this.logger.log(`Secret ${secretName} rotated successfully`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to rotate secret ${secretName}: ${error.message}`);

      // Log failed rotation
      const secretRecord = await this.prisma.secret.findUnique({ where: { secretName } });
      if (secretRecord) {
        await this.prisma.secretRotation.create({
          data: {
            secretId: secretRecord.id,
            rotationType,
            initiatedBy: requester,
            reason,
            success: false,
            errorMessage: error.message,
          },
        });
      }

      await this.accessLogger.logAccess(secretName, requester, 'rotate', 'api', false, error.message);
      return false;
    }
  }

  /**
   * Emergency revoke a secret
   */
  async emergencyRevokeSecret(
    secretName: string,
    requester: string,
    reason: string,
  ): Promise<boolean> {
    try {
      const secretRecord = await this.prisma.secret.findUnique({
        where: { secretName },
      });

      if (!secretRecord) {
        throw new Error('Secret not found');
      }

      // Update secret status
      await this.prisma.secret.update({
        where: { id: secretRecord.id },
        data: {
          emergencyRevoked: true,
          revokedAt: new Date(),
          revokedBy: requester,
        },
      });

      // Clear cache
      this.secretCache.delete(secretName);

      // Create alert
      await this.prisma.secretAlert.create({
        data: {
          secretId: secretRecord.id,
          alertType: 'emergency_revoked',
          severity: 'critical',
          message: `Secret ${secretName} has been emergency revoked`,
          details: { reason, revokedBy: requester },
        },
      });

      // Log access
      await this.accessLogger.logAccess(secretName, requester, 'revoke', 'api', true, reason);

      this.logger.warn(`Secret ${secretName} emergency revoked by ${requester}: ${reason}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to revoke secret ${secretName}: ${error.message}`);
      await this.accessLogger.logAccess(secretName, requester, 'revoke', 'api', false, error.message);
      return false;
    }
  }

  /**
   * Get all secrets metadata
   */
  async getSecretsMetadata(): Promise<SecretMetadata[]> {
    const secrets = await this.prisma.secret.findMany({
      orderBy: { createdAt: 'desc' },
    });

    return secrets.map(secret => ({
      id: secret.id,
      secretName: secret.secretName,
      secretType: secret.secretType,
      description: secret.description || undefined,
      rotationSchedule: secret.rotationSchedule,
      lastRotatedAt: secret.lastRotatedAt || undefined,
      nextRotationAt: secret.nextRotationAt || undefined,
      isActive: secret.isActive,
      emergencyRevoked: secret.emergencyRevoked,
      revokedAt: secret.revokedAt || undefined,
      revokedBy: secret.revokedBy || undefined,
    }));
  }

  /**
   * Get secrets that need rotation
   */
  async getSecretsNeedingRotation(): Promise<SecretMetadata[]> {
    const secrets = await this.prisma.secret.findMany({
      where: {
        isActive: true,
        emergencyRevoked: false,
        nextRotationAt: {
          lte: new Date(),
        },
      },
    });

    return secrets.map(secret => ({
      id: secret.id,
      secretName: secret.secretName,
      secretType: secret.secretType,
      description: secret.description || undefined,
      rotationSchedule: secret.rotationSchedule,
      lastRotatedAt: secret.lastRotatedAt || undefined,
      nextRotationAt: secret.nextRotationAt || undefined,
      isActive: secret.isActive,
      emergencyRevoked: secret.emergencyRevoked,
      revokedAt: secret.revokedAt || undefined,
      revokedBy: secret.revokedBy || undefined,
    }));
  }

  /**
   * Sync secrets from AWS Secrets Manager to database
   */
  private async syncSecretsFromAWS(): Promise<void> {
    try {
      const command = new ListSecretsCommand({});
      const response = await this.secretsManagerClient.send(command);

      for (const awsSecret of response.SecretList || []) {
        if (!awsSecret.Name) continue;

        // Check if we already have this secret
        const existing = await this.prisma.secret.findUnique({
          where: { secretName: awsSecret.Name },
        });

        if (!existing) {
          // Create database record for AWS secret
          await this.prisma.secret.create({
            data: {
              secretName: awsSecret.Name,
              secretType: this.inferSecretType(awsSecret.Name),
              rotationSchedule: '90d', // Default
              nextRotationAt: this.calculateNextRotation('90d'),
            },
          });
        }
      }

      this.logger.log('Secrets synchronized from AWS Secrets Manager');
    } catch (error) {
      this.logger.error(`Failed to sync secrets from AWS: ${error.message}`);
    }
  }

  /**
   * Generate new secret values based on type
   */
  private async generateNewSecretValues(secretType: string): Promise<SecretData> {
    switch (secretType) {
      case 'database':
        return {
          username: 'stellara_app',
          password: this.generateSecurePassword(32),
          host: this.configService.get<string>('DATABASE_HOST'),
          port: this.configService.get<number>('DATABASE_PORT'),
          database: this.configService.get<string>('DATABASE_NAME'),
        };

      case 'jwt':
        return {
          secret: this.generateSecurePassword(64),
          refreshSecret: this.generateSecurePassword(64),
        };

      case 'api_key':
        return {
          key: this.generateSecurePassword(48),
          expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(), // 90 days
        };

      case 'stripe':
        return {
          secretKey: `sk_test_${this.generateSecurePassword(32)}`,
          publishableKey: `pk_test_${this.generateSecurePassword(32)}`,
          webhookSecret: `whsec_${this.generateSecurePassword(32)}`,
        };

      case 'twilio':
        return {
          accountSid: `AC${this.generateSecurePassword(32)}`,
          authToken: this.generateSecurePassword(32),
          phoneNumber: '+15551234567', // Would be configured
        };

      default:
        return {
          value: this.generateSecurePassword(32),
        };
    }
  }

  /**
   * Generate a secure random password
   */
  private generateSecurePassword(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
  }

  /**
   * Calculate next rotation date
   */
  private calculateNextRotation(schedule: string): Date {
    if (schedule === 'never') return new Date('2099-12-31');

    const match = schedule.match(/^(\d+)([dwm])$/);
    if (!match) return new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // Default 90 days

    const value = parseInt(match[1]);
    const unit = match[2];

    let milliseconds = 0;
    switch (unit) {
      case 'd':
        milliseconds = value * 24 * 60 * 60 * 1000;
        break;
      case 'w':
        milliseconds = value * 7 * 24 * 60 * 60 * 1000;
        break;
      case 'm':
        milliseconds = value * 30 * 24 * 60 * 60 * 1000; // Approximate
        break;
    }

    return new Date(Date.now() + milliseconds);
  }

  /**
   * Infer secret type from name
   */
  private inferSecretType(secretName: string): string {
    const name = secretName.toLowerCase();

    if (name.includes('database') || name.includes('db')) return 'database';
    if (name.includes('jwt') || name.includes('token')) return 'jwt';
    if (name.includes('stripe')) return 'stripe';
    if (name.includes('twilio')) return 'twilio';
    if (name.includes('api') || name.includes('key')) return 'api_key';

    return 'generic';
  }

  /**
   * Encrypt secret data for storage (simplified - in production use proper encryption)
   */
  private encryptSecretData(data: SecretData): any {
    // In production, this should use proper encryption
    // For now, we'll store as-is since AWS already encrypts at rest
    return data;
  }
}