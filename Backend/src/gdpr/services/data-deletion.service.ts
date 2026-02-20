import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { WalletBinding } from '../../auth/entities/wallet-binding.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { ApiToken } from '../../auth/entities/api-token.entity';
import { AuditService } from '../../audit/audit.service';
import { Consent } from '../entities/consent.entity';

export interface DeletionRequest {
  id: string;
  userId: string;
  status: 'pending' | 'processing' | 'completed' | 'cancelled';
  requestedAt: Date;
  processedAt?: Date;
  retentionUntil?: Date;
  reason?: string;
}

export interface DeletionStats {
  user: boolean;
  wallets: number;
  refreshTokens: number;
  apiTokens: number;
  consents: number;
  auditLogs: number;
}

@Injectable()
export class DataDeletionService {
  private readonly RETENTION_DAYS = 30; // Configurable retention period

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(WalletBinding)
    private readonly walletRepository: Repository<WalletBinding>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(ApiToken)
    private readonly apiTokenRepository: Repository<ApiToken>,
    @InjectRepository(Consent)
    private readonly consentRepository: Repository<Consent>,
    private readonly auditService: AuditService,
  ) {}

  async requestDeletion(userId: string, reason?: string): Promise<DeletionRequest> {
    // Verify user exists and is active
    const user = await this.userRepository.findOne({
      where: { id: userId, isActive: true },
    });

    if (!user) {
      throw new NotFoundException('User not found or inactive');
    }

    // Create deletion request with retention period
    const retentionUntil = new Date();
    retentionUntil.setDate(retentionUntil.getDate() + this.RETENTION_DAYS);

    const deletionRequest: DeletionRequest = {
      id: `del_${Date.now()}_${userId.substring(0, 8)}`,
      userId,
      status: 'pending',
      requestedAt: new Date(),
      retentionUntil,
      reason,
    };

    // Mark user as inactive (soft deletion)
    await this.userRepository.update(userId, {
      isActive: false,
    });

    // Log the deletion request
    await this.auditService.logAction('DELETION_REQUESTED', userId, userId, {
      deletionRequestId: deletionRequest.id,
      reason,
      retentionUntil,
    });

    return deletionRequest;
  }

  async processDeletion(deletionRequestId: string, adminId: string): Promise<DeletionStats> {
    // In a real implementation, you would fetch the deletion request from a database
    // For now, we'll extract userId from the request ID
    const userId = deletionRequestId.split('_')[2];

    if (!userId) {
      throw new NotFoundException('Invalid deletion request ID');
    }

    // Verify user exists and is marked for deletion
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isActive) {
      throw new ForbiddenException('User account is not marked for deletion');
    }

    // Log admin action
    await this.auditService.logAction('DELETION_PROCESSING_STARTED', adminId, userId, {
      deletionRequestId,
    });

    // Perform soft deletion of related data
    const [walletStats, refreshTokenStats, apiTokenStats, consentStats] = await Promise.all([
      this.softDeleteWallets(userId),
      this.softDeleteRefreshTokens(userId),
      this.softDeleteApiTokens(userId),
      this.softDeleteConsents(userId),
    ]);

    // Update user record with deletion metadata
    await this.userRepository.update(userId, {
      email: undefined, // Remove PII
      username: `deleted_${userId.substring(0, 8)}`,
    });

    // Log completion
    const stats: DeletionStats = {
      user: true,
      wallets: walletStats,
      refreshTokens: refreshTokenStats,
      apiTokens: apiTokenStats,
      consents: consentStats,
      auditLogs: 0, // Audit logs are retained for compliance
    };

    await this.auditService.logAction('DELETION_COMPLETED', adminId, userId, {
      deletionRequestId,
      stats,
    });

    return stats;
  }

  async cancelDeletion(userId: string): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId, isActive: false },
    });

    if (!user) {
      throw new NotFoundException('Inactive user not found');
    }

    // Restore user account
    await this.userRepository.update(userId, {
      isActive: true,
    });

    await this.auditService.logAction('DELETION_CANCELLED', userId, userId);
  }

  async hardDeleteExpiredData(): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_DAYS);

    // Find users marked for deletion beyond retention period
    const expiredUsers = await this.userRepository.find({
      where: {
        isActive: false,
        updatedAt: In([cutoffDate]),
      },
    });

    let deletedCount = 0;

    for (const user of expiredUsers) {
      // Perform hard deletion of all user data
      await this.hardDeleteUserData(user.id);
      deletedCount++;
      
      await this.auditService.logAction('HARD_DELETION_COMPLETED', 'system', user.id, {
        reason: 'Retention period expired',
      });
    }

    return deletedCount;
  }

  private async softDeleteWallets(userId: string): Promise<number> {
    const result = await this.walletRepository.update(
      { userId },
      { 
        publicKey: `deleted_${Date.now()}`, // Anonymize
      },
    );
    return result.affected || 0;
  }

  private async softDeleteRefreshTokens(userId: string): Promise<number> {
    const result = await this.refreshTokenRepository.update(
      { userId },
      { 
        revoked: true,
        revokedAt: new Date(),
        token: `deleted_${Date.now()}`, // Anonymize
      },
    );
    return result.affected || 0;
  }

  private async softDeleteApiTokens(userId: string): Promise<number> {
    const result = await this.apiTokenRepository.update(
      { userId },
      { 
        revoked: true,
        token: `deleted_${Date.now()}`, // Anonymize
      },
    );
    return result.affected || 0;
  }

  private async softDeleteConsents(userId: string): Promise<number> {
    const result = await this.consentRepository.update(
      { userId },
      { 
        withdrawnAt: new Date(),
      },
    );
    return result.affected || 0;
  }

  private async hardDeleteUserData(userId: string): Promise<void> {
    // Delete in order of dependencies
    await this.consentRepository.delete({ userId });
    await this.apiTokenRepository.delete({ userId });
    await this.refreshTokenRepository.delete({ userId });
    await this.walletRepository.delete({ userId });
    
    // Finally delete the user
    await this.userRepository.delete(userId);
  }

  async getDeletionStatus(userId: string): Promise<{ 
    isActive: boolean; 
    deletionRequested?: Date; 
    retentionUntil?: Date 
  }> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      isActive: user.isActive,
      deletionRequested: user.isActive ? undefined : user.updatedAt,
      retentionUntil: user.isActive ? undefined : 
        new Date(user.updatedAt.getTime() + (this.RETENTION_DAYS * 24 * 60 * 60 * 1000)),
    };
  }
}