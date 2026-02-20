import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Consent, ConsentType, ConsentStatus } from '../entities/consent.entity';
import { AuditService } from '../../audit/audit.service';

export interface ConsentData {
  consentType: ConsentType;
  granted: boolean;
  version?: string;
  consentText?: string;
}

export interface ConsentHistory {
  consentType: ConsentType;
  history: Array<{
    status: ConsentStatus;
    grantedAt?: Date;
    withdrawnAt?: Date;
    version: string;
  }>;
}

@Injectable()
export class ConsentManagementService {
  private readonly DEFAULT_CONSENT_VERSION = '1.0.0';

  constructor(
    @InjectRepository(Consent)
    private readonly consentRepository: Repository<Consent>,
    private readonly auditService: AuditService,
  ) {}

  async getConsentStatus(userId: string, consentType: ConsentType): Promise<Consent | null> {
    return await this.consentRepository.findOne({
      where: { userId, consentType },
    });
  }

  async getAllConsents(userId: string): Promise<Consent[]> {
    return await this.consentRepository.find({
      where: { userId },
      order: { updatedAt: 'DESC' },
    });
  }

  async grantConsent(userId: string, consentData: ConsentData): Promise<Consent> {
    const existingConsent = await this.consentRepository.findOne({
      where: { userId, consentType: consentData.consentType },
    });

    const consentVersion = consentData.version || this.DEFAULT_CONSENT_VERSION;

    if (existingConsent) {
      // Update existing consent
      existingConsent.status = ConsentStatus.GRANTED;
      existingConsent.version = consentVersion;
      existingConsent.consentText = consentData.consentText;
      existingConsent.grantedAt = new Date();
      existingConsent.withdrawnAt = undefined;
      existingConsent.expiresAt = this.calculateExpiryDate(consentData.consentType);

      const updatedConsent = await this.consentRepository.save(existingConsent);

      await this.auditService.logAction('CONSENT_GRANTED', userId, updatedConsent.id, {
        consentType: consentData.consentType,
        version: consentVersion,
        updated: true,
      });

      return updatedConsent;
    } else {
      // Create new consent
      const newConsent = this.consentRepository.create({
        userId,
        consentType: consentData.consentType,
        status: ConsentStatus.GRANTED,
        version: consentVersion,
        consentText: consentData.consentText,
        grantedAt: new Date(),
        expiresAt: this.calculateExpiryDate(consentData.consentType),
      });

      const savedConsent = await this.consentRepository.save(newConsent);

      await this.auditService.logAction('CONSENT_GRANTED', userId, savedConsent.id, {
        consentType: consentData.consentType,
        version: consentVersion,
        updated: false,
      });

      return savedConsent;
    }
  }

  async withdrawConsent(userId: string, consentType: ConsentType): Promise<Consent> {
    const consent = await this.consentRepository.findOne({
      where: { userId, consentType },
    });

    if (!consent) {
      throw new NotFoundException('Consent not found');
    }

    if (consent.status === ConsentStatus.WITHDRAWN) {
      return consent; // Already withdrawn
    }

    consent.status = ConsentStatus.WITHDRAWN;
    consent.withdrawnAt = new Date();

    const updatedConsent = await this.consentRepository.save(consent);

    await this.auditService.logAction('CONSENT_WITHDRAWN', userId, updatedConsent.id, {
      consentType,
    });

    return updatedConsent;
  }

  async updateConsentVersion(
    consentType: ConsentType,
    newVersion: string,
    consentText: string,
  ): Promise<number> {
    // Find all active consents of this type
    const activeConsents = await this.consentRepository.find({
      where: { 
        consentType,
        status: ConsentStatus.GRANTED,
      },
    });

    // Update all active consents to the new version
    const updatePromises = activeConsents.map(consent => {
      consent.version = newVersion;
      consent.consentText = consentText;
      consent.expiresAt = this.calculateExpiryDate(consentType);
      return this.consentRepository.save(consent);
    });

    await Promise.all(updatePromises);

    await this.auditService.logAction('CONSENT_VERSION_UPDATED', 'system', consentType, {
      oldVersion: activeConsents[0]?.version || 'N/A',
      newVersion,
      affectedCount: activeConsents.length,
    });

    return activeConsents.length;
  }

  async getConsentHistory(userId: string, consentType: ConsentType): Promise<ConsentHistory> {
    const consents = await this.consentRepository.find({
      where: { userId, consentType },
      order: { grantedAt: 'ASC' },
    });

    const history = consents.map(consent => ({
      status: consent.status,
      grantedAt: consent.grantedAt,
      withdrawnAt: consent.withdrawnAt,
      version: consent.version,
    }));

    return {
      consentType,
      history,
    };
  }

  async getConsentAnalytics(): Promise<Record<ConsentType, {
    total: number;
    granted: number;
    withdrawn: number;
    expired: number;
  }>> {
    const allConsents = await this.consentRepository.find();

    const analytics: Record<ConsentType, {
      total: number;
      granted: number;
      withdrawn: number;
      expired: number;
    }> = {
      [ConsentType.DATA_PROCESSING]: { total: 0, granted: 0, withdrawn: 0, expired: 0 },
      [ConsentType.MARKETING]: { total: 0, granted: 0, withdrawn: 0, expired: 0 },
      [ConsentType.ANALYTICS]: { total: 0, granted: 0, withdrawn: 0, expired: 0 },
      [ConsentType.THIRD_PARTY_SHARING]: { total: 0, granted: 0, withdrawn: 0, expired: 0 },
    };

    for (const consent of allConsents) {
      analytics[consent.consentType].total++;
      
      switch (consent.status) {
        case ConsentStatus.GRANTED:
          analytics[consent.consentType].granted++;
          break;
        case ConsentStatus.WITHDRAWN:
          analytics[consent.consentType].withdrawn++;
          break;
        case ConsentStatus.EXPIRED:
          analytics[consent.consentType].expired++;
          break;
      }
    }

    return analytics;
  }

  async expireOutdatedConsents(): Promise<number> {
    const now = new Date();
    const expiredConsents = await this.consentRepository.find({
      where: {
        status: ConsentStatus.GRANTED,
        expiresAt: new Date(now.getTime() - 24 * 60 * 60 * 1000), // Expired at least 1 day ago
      },
    });

    const updatePromises = expiredConsents.map(consent => {
      consent.status = ConsentStatus.EXPIRED;
      return this.consentRepository.save(consent);
    });

    await Promise.all(updatePromises);

    if (expiredConsents.length > 0) {
      await this.auditService.logAction('CONSENTS_EXPIRED', 'system', 'batch', {
        count: expiredConsents.length,
      });
    }

    return expiredConsents.length;
  }

  async validateConsent(userId: string, consentType: ConsentType): Promise<boolean> {
    const consent = await this.getConsentStatus(userId, consentType);
    
    if (!consent) {
      return false;
    }

    // Check if consent is granted and not expired
    if (consent.status !== ConsentStatus.GRANTED) {
      return false;
    }

    // Check expiration
    if (consent.expiresAt && new Date() > consent.expiresAt) {
      // Auto-expire the consent
      await this.expireConsent(consent.id);
      return false;
    }

    return true;
  }

  private async expireConsent(consentId: string): Promise<void> {
    await this.consentRepository.update(consentId, {
      status: ConsentStatus.EXPIRED,
    });
  }

  private calculateExpiryDate(consentType: ConsentType): Date {
    const now = new Date();
    const expiryDays = this.getExpiryDays(consentType);
    const expiryDate = new Date(now.getTime() + (expiryDays * 24 * 60 * 60 * 1000));
    return expiryDate;
  }

  private getExpiryDays(consentType: ConsentType): number {
    // Different expiry periods based on consent type
    switch (consentType) {
      case ConsentType.DATA_PROCESSING:
        return 365 * 5; // 5 years
      case ConsentType.MARKETING:
        return 365; // 1 year
      case ConsentType.ANALYTICS:
        return 365; // 1 year
      case ConsentType.THIRD_PARTY_SHARING:
        return 180; // 6 months
      default:
        return 365; // 1 year default
    }
  }
}