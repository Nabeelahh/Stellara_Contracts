// src/secrets-management/secret-rotation.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { SecretsManagementService } from './secrets-management.service';
import { SecretAccessLoggerService } from './secret-access-logger.service';

@Injectable()
export class SecretRotationService {
  private readonly logger = new Logger(SecretRotationService.name);

  constructor(
    private prisma: PrismaService,
    private secretsService: SecretsManagementService,
    private accessLogger: SecretAccessLoggerService,
  ) {}

  /**
   * Scheduled rotation check - runs every hour
   */
  @Cron(CronExpression.EVERY_HOUR)
  async checkAndRotateSecrets(): Promise<void> {
    try {
      this.logger.log('Checking for secrets that need rotation...');

      const secretsNeedingRotation = await this.secretsService.getSecretsNeedingRotation();

      if (secretsNeedingRotation.length === 0) {
        this.logger.debug('No secrets need rotation at this time');
        return;
      }

      this.logger.log(`Found ${secretsNeedingRotation.length} secrets needing rotation`);

      for (const secret of secretsNeedingRotation) {
        try {
          const success = await this.secretsService.rotateSecret(
            secret.secretName,
            'scheduled',
            'rotation-service',
            'Scheduled rotation based on rotation schedule',
          );

          if (success) {
            this.logger.log(`Successfully rotated secret: ${secret.secretName}`);
          } else {
            this.logger.error(`Failed to rotate secret: ${secret.secretName}`);
            await this.createRotationFailureAlert(secret.secretName);
          }
        } catch (error) {
          this.logger.error(`Error rotating secret ${secret.secretName}: ${error.message}`);
          await this.createRotationFailureAlert(secret.secretName, error.message);
        }
      }
    } catch (error) {
      this.logger.error(`Error in scheduled rotation check: ${error.message}`);
    }
  }

  /**
   * Manual rotation of a specific secret
   */
  async rotateSecretManually(
    secretName: string,
    requester: string,
    reason?: string,
  ): Promise<{ success: boolean; message: string }> {
    try {
      this.logger.log(`Manual rotation requested for secret: ${secretName} by ${requester}`);

      const success = await this.secretsService.rotateSecret(
        secretName,
        'manual',
        requester,
        reason || 'Manual rotation requested',
      );

      if (success) {
        return {
          success: true,
          message: `Secret ${secretName} rotated successfully`,
        };
      } else {
        return {
          success: false,
          message: `Failed to rotate secret ${secretName}`,
        };
      }
    } catch (error) {
      this.logger.error(`Manual rotation failed for ${secretName}: ${error.message}`);
      return {
        success: false,
        message: `Error rotating secret ${secretName}: ${error.message}`,
      };
    }
  }

  /**
   * Bulk rotate secrets by type
   */
  async rotateSecretsByType(
    secretType: string,
    requester: string,
    reason?: string,
  ): Promise<{ success: boolean; results: Array<{ secretName: string; success: boolean; message: string }> }> {
    try {
      this.logger.log(`Bulk rotation requested for type: ${secretType} by ${requester}`);

      const secrets = await this.prisma.secret.findMany({
        where: {
          secretType,
          isActive: true,
          emergencyRevoked: false,
        },
      });

      const results = [];

      for (const secret of secrets) {
        try {
          const success = await this.secretsService.rotateSecret(
            secret.secretName,
            'manual',
            requester,
            reason || `Bulk rotation of ${secretType} secrets`,
          );

          results.push({
            secretName: secret.secretName,
            success,
            message: success ? 'Rotated successfully' : 'Rotation failed',
          });
        } catch (error) {
          results.push({
            secretName: secret.secretName,
            success: false,
            message: `Error: ${error.message}`,
          });
        }
      }

      const successCount = results.filter(r => r.success).length;
      const totalCount = results.length;

      this.logger.log(`Bulk rotation completed: ${successCount}/${totalCount} secrets rotated successfully`);

      return {
        success: successCount > 0,
        results,
      };
    } catch (error) {
      this.logger.error(`Bulk rotation failed for type ${secretType}: ${error.message}`);
      return {
        success: false,
        results: [],
      };
    }
  }

  /**
   * Emergency rotation of all secrets (for security incidents)
   */
  async emergencyRotateAllSecrets(
    requester: string,
    reason: string,
  ): Promise<{ success: boolean; results: Array<{ secretName: string; success: boolean; message: string }> }> {
    try {
      this.logger.warn(`Emergency rotation of ALL secrets initiated by ${requester}: ${reason}`);

      const secrets = await this.prisma.secret.findMany({
        where: {
          isActive: true,
          emergencyRevoked: false,
        },
      });

      const results = [];

      for (const secret of secrets) {
        try {
          const success = await this.secretsService.rotateSecret(
            secret.secretName,
            'emergency',
            requester,
            `Emergency rotation: ${reason}`,
          );

          results.push({
            secretName: secret.secretName,
            success,
            message: success ? 'Emergency rotated successfully' : 'Emergency rotation failed',
          });
        } catch (error) {
          results.push({
            secretName: secret.secretName,
            success: false,
            message: `Error: ${error.message}`,
          });
        }
      }

      const successCount = results.filter(r => r.success).length;
      const totalCount = results.length;

      this.logger.warn(`Emergency rotation completed: ${successCount}/${totalCount} secrets rotated`);

      // Create emergency alert
      await this.prisma.secretAlert.create({
        data: {
          alertType: 'emergency_rotation',
          severity: 'critical',
          message: `Emergency rotation of all secrets completed by ${requester}`,
          details: {
            reason,
            totalSecrets: totalCount,
            successfulRotations: successCount,
            failedRotations: totalCount - successCount,
            results,
          },
        },
      });

      return {
        success: successCount > 0,
        results,
      };
    } catch (error) {
      this.logger.error(`Emergency rotation failed: ${error.message}`);
      return {
        success: false,
        results: [],
      };
    }
  }

  /**
   * Update rotation schedule for a secret
   */
  async updateRotationSchedule(
    secretName: string,
    newSchedule: string,
    requester: string,
  ): Promise<{ success: boolean; message: string }> {
    try {
      const secret = await this.prisma.secret.findUnique({
        where: { secretName },
      });

      if (!secret) {
        return {
          success: false,
          message: `Secret ${secretName} not found`,
        };
      }

      // Calculate new next rotation date
      const nextRotationAt = this.calculateNextRotation(newSchedule);

      await this.prisma.secret.update({
        where: { id: secret.id },
        data: {
          rotationSchedule: newSchedule,
          nextRotationAt,
        },
      });

      // Log the change
      await this.accessLogger.logAccess(
        secretName,
        requester,
        'write',
        'api',
        true,
        `Rotation schedule updated to ${newSchedule}`,
      );

      this.logger.log(`Updated rotation schedule for ${secretName} to ${newSchedule}`);

      return {
        success: true,
        message: `Rotation schedule updated to ${newSchedule}`,
      };
    } catch (error) {
      this.logger.error(`Failed to update rotation schedule for ${secretName}: ${error.message}`);
      return {
        success: false,
        message: `Error updating rotation schedule: ${error.message}`,
      };
    }
  }

  /**
   * Get rotation status for all secrets
   */
  async getRotationStatus(): Promise<Array<{
    secretName: string;
    secretType: string;
    rotationSchedule: string;
    lastRotatedAt?: Date;
    nextRotationAt?: Date;
    daysUntilRotation: number;
    needsRotation: boolean;
  }>> {
    const secrets = await this.prisma.secret.findMany({
      where: {
        isActive: true,
        emergencyRevoked: false,
      },
      orderBy: { nextRotationAt: 'asc' },
    });

    const now = new Date();

    return secrets.map(secret => {
      const nextRotation = secret.nextRotationAt || new Date('2099-12-31');
      const daysUntilRotation = Math.max(0, Math.ceil((nextRotation.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)));

      return {
        secretName: secret.secretName,
        secretType: secret.secretType,
        rotationSchedule: secret.rotationSchedule,
        lastRotatedAt: secret.lastRotatedAt || undefined,
        nextRotationAt: secret.nextRotationAt || undefined,
        daysUntilRotation,
        needsRotation: nextRotation <= now,
      };
    });
  }

  /**
   * Force immediate rotation (bypasses schedule)
   */
  async forceRotateSecret(
    secretName: string,
    requester: string,
    reason: string,
  ): Promise<{ success: boolean; message: string }> {
    try {
      this.logger.log(`Force rotation requested for ${secretName} by ${requester}: ${reason}`);

      const success = await this.secretsService.rotateSecret(
        secretName,
        'manual',
        requester,
        `Force rotation: ${reason}`,
      );

      if (success) {
        return {
          success: true,
          message: `Secret ${secretName} force rotated successfully`,
        };
      } else {
        return {
          success: false,
          message: `Failed to force rotate secret ${secretName}`,
        };
      }
    } catch (error) {
      this.logger.error(`Force rotation failed for ${secretName}: ${error.message}`);
      return {
        success: false,
        message: `Error force rotating secret ${secretName}: ${error.message}`,
      };
    }
  }

  /**
   * Create alert for rotation failure
   */
  private async createRotationFailureAlert(secretName: string, errorMessage?: string): Promise<void> {
    try {
      const secret = await this.prisma.secret.findUnique({ where: { secretName } });

      await this.prisma.secretAlert.create({
        data: {
          secretId: secret?.id,
          alertType: 'rotation_failed',
          severity: 'high',
          message: `Failed to rotate secret ${secretName}`,
          details: {
            secretName,
            errorMessage: errorMessage || 'Unknown error',
            lastAttempt: new Date().toISOString(),
          },
        },
      });
    } catch (error) {
      this.logger.error(`Failed to create rotation failure alert: ${error.message}`);
    }
  }

  /**
   * Calculate next rotation date from schedule string
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
}