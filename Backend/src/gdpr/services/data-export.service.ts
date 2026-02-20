import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { WalletBinding } from '../../auth/entities/wallet-binding.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { ApiToken } from '../../auth/entities/api-token.entity';
import { AuditLog } from '../../audit/audit.entity';
import { AuditService } from '../../audit/audit.service';
import { Consent } from '../entities/consent.entity';

export interface UserDataExport {
  user: {
    id: string;
    email?: string;
    username?: string;
    createdAt: Date;
    updatedAt: Date;
    isActive: boolean;
  };
  wallets: Array<{
    id: string;
    publicKey: string;
    createdAt: Date;
    lastUsedAt?: Date;
  }>;
  refreshTokens: Array<{
    id: string;
    createdAt: Date;
    expiresAt: Date;
    lastUsedAt?: Date;
    revoked: boolean;
    revokedAt?: Date;
  }>;
  apiTokens: Array<{
    id: string;
    name: string;
    createdAt: Date;
    lastUsedAt?: Date;
    expiresAt?: Date;
    revoked: boolean;
  }>;
  auditLogs: Array<{
    id: string;
    action_type: string;
    timestamp: Date;
    metadata?: Record<string, any>;
  }>;
  consents: Array<{
    id: string;
    consentType: string;
    status: string;
    version: string;
    grantedAt: Date;
    withdrawnAt?: Date;
    expiresAt?: Date;
  }>;
}

@Injectable()
export class DataExportService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(WalletBinding)
    private readonly walletRepository: Repository<WalletBinding>,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(ApiToken)
    private readonly apiTokenRepository: Repository<ApiToken>,
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
    @InjectRepository(Consent)
    private readonly consentRepository: Repository<Consent>,
    private readonly auditService: AuditService,
  ) {}

  async exportUserData(userId: string): Promise<UserDataExport> {
    // Verify user exists and is active
    const user = await this.userRepository.findOne({
      where: { id: userId, isActive: true },
    });

    if (!user) {
      throw new NotFoundException('User not found or inactive');
    }

    // Log the export request
    await this.auditService.logAction('DATA_EXPORT_REQUESTED', userId, userId, {
      exportType: 'personal_data',
    });

    // Fetch all related data
    const [wallets, refreshTokens, apiTokens, auditLogs, consents] = await Promise.all([
      this.walletRepository.find({ where: { userId } }),
      this.refreshTokenRepository.find({ where: { userId } }),
      this.apiTokenRepository.find({ where: { userId } }),
      this.auditLogRepository.find({ 
        where: { actor_id: userId },
        order: { timestamp: 'DESC' },
        take: 1000, // Limit for performance
      }),
      this.consentRepository.find({ where: { userId } }),
    ]);

    const exportData: UserDataExport = {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        isActive: user.isActive,
      },
      wallets: wallets.map(wallet => ({
        id: wallet.id,
        publicKey: wallet.publicKey,
        createdAt: wallet.boundAt,
        lastUsedAt: wallet.lastUsed,
      })),
      refreshTokens: refreshTokens.map(token => ({
        id: token.id,
        createdAt: token.createdAt,
        expiresAt: token.expiresAt,
        lastUsedAt: undefined, // RefreshToken doesn't have lastUsedAt property
        revoked: token.revoked,
        revokedAt: token.revokedAt,
      })),
      apiTokens: apiTokens.map(token => ({
        id: token.id,
        name: token.name,
        createdAt: token.createdAt,
        lastUsedAt: token.lastUsedAt,
        expiresAt: token.expiresAt,
        revoked: token.revoked,
      })),
      auditLogs: auditLogs.map(log => ({
        id: log.id,
        action_type: log.action_type,
        timestamp: log.timestamp,
        metadata: log.metadata,
      })),
      consents: consents.map(consent => ({
        id: consent.id,
        consentType: consent.consentType,
        status: consent.status,
        version: consent.version,
        grantedAt: consent.grantedAt,
        withdrawnAt: consent.withdrawnAt,
        expiresAt: consent.expiresAt,
      })),
    };

    // Log successful export completion
    await this.auditService.logAction('DATA_EXPORT_COMPLETED', userId, userId, {
      exportType: 'personal_data',
      dataPoints: {
        user: 1,
        wallets: wallets.length,
        refreshTokens: refreshTokens.length,
        apiTokens: apiTokens.length,
        auditLogs: auditLogs.length,
        consents: consents.length,
      },
    });

    return exportData;
  }

  async exportUserDataAsJson(userId: string): Promise<string> {
    const data = await this.exportUserData(userId);
    return JSON.stringify(data, null, 2);
  }

  async exportUserDataAsCsv(userId: string): Promise<string> {
    const data = await this.exportUserData(userId);
    
    // Simple CSV export - in production, use a proper CSV library
    let csv = 'Data Type,Data\n';
    
    // User data
    csv += `User ID,${data.user.id}\n`;
    csv += `Email,${data.user.email || 'N/A'}\n`;
    csv += `Username,${data.user.username || 'N/A'}\n`;
    csv += `Created At,${data.user.createdAt.toISOString()}\n`;
    csv += `Updated At,${data.user.updatedAt.toISOString()}\n`;
    csv += `Is Active,${data.user.isActive}\n`;
    
    // Add section headers and data for other entities
    csv += '\nWallets:\n';
    csv += 'ID,Public Key,Created At,Last Used\n';
    data.wallets.forEach(wallet => {
      csv += `${wallet.id},${wallet.publicKey},${wallet.createdAt.toISOString()},${wallet.lastUsedAt?.toISOString() || 'N/A'}\n`;
    });
    
    return csv;
  }
}