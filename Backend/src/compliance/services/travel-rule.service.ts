import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TravelRuleDataDto } from '../dto/compliance.dto';

export interface TravelRuleRecord {
  id: string;
  transactionHash: string;
  originatorName: string;
  originatorAddress: string;
  originatorAccountNumber?: string;
  beneficiaryName: string;
  beneficiaryAddress: string;
  beneficiaryAccountNumber?: string;
  amountUsdCents: number;
  timestamp: Date;
  status: 'PENDING' | 'COMPLIANT' | 'NON_COMPLIANT' | 'EXEMPTED';
  exemptionReason?: string;
  dataCollected: boolean;
  verificationStatus: 'UNVERIFIED' | 'VERIFIED' | 'FAILED';
}

@Injectable()
export class TravelRuleService {
  private readonly logger = new Logger(TravelRuleService.name);
  private readonly THRESHOLD_USD_CENTS = 100000; // $1,000 USD in cents

  constructor(
    @InjectRepository('travel_rule_records')
    private readonly travelRuleRepo: Repository<any>,
  ) {}

  /**
   * Check if transfer requires Travel Rule compliance
   */
  requiresTravelRuleCompliance(amountUsdCents: number): boolean {
    return amountUsdCents >= this.THRESHOLD_USD_CENTS;
  }

  /**
   * Collect and validate Travel Rule data for transfers >$1,000
   */
  async collectTravelRuleData(data: TravelRuleDataDto): Promise<{
    isCompliant: boolean;
    recordId: string;
    missingFields: string[];
    warnings: string[];
  }> {
    const missingFields: string[] = [];
    const warnings: string[] = [];

    // Validate required fields per FATF guidance
    if (!data.originatorName || data.originatorName.trim().length === 0) {
      missingFields.push('originatorName');
    }

    if (!data.originatorAddress || data.originatorAddress.trim().length === 0) {
      missingFields.push('originatorAddress');
    }

    if (!data.beneficiaryName || data.beneficiaryName.trim().length === 0) {
      missingFields.push('beneficiaryName');
    }

    if (!data.beneficiaryAddress || data.beneficiaryAddress.trim().length === 0) {
      missingFields.push('beneficiaryAddress');
    }

    // Check if transfer exceeds threshold
    const requiresCompliance = this.requiresTravelRuleCompliance(data.amountUsdCents);

    if (requiresCompliance && missingFields.length > 0) {
      throw new Error(
        `Travel Rule compliance required. Missing fields: ${missingFields.join(', ')}`,
      );
    }

    // Create travel rule record
    const record = await this.travelRuleRepo.save({
      transactionHash: data.transactionHash || `pending_${Date.now()}`,
      originatorName: data.originatorName,
      originatorAddress: data.originatorAddress,
      originatorAccountNumber: data.originatorAccountNumber,
      beneficiaryName: data.beneficiaryName,
      beneficiaryAddress: data.beneficiaryAddress,
      beneficiaryAccountNumber: data.beneficiaryAccountNumber,
      amountUsdCents: data.amountUsdCents,
      status: missingFields.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
      dataCollected: true,
      verificationStatus: 'UNVERIFIED',
      timestamp: new Date(),
    });

    this.logger.log(`Travel Rule record created: ${record.id}`);

    return {
      isCompliant: missingFields.length === 0,
      recordId: record.id,
      missingFields,
      warnings,
    };
  }

  /**
   * Verify Travel Rule data with VASP (Virtual Asset Service Provider)
   */
  async verifyWithVASP(recordId: string, vaspData: {
    vaspIdentifier: string;
    verificationCode: string;
  }): Promise<boolean> {
    const record = await this.travelRuleRepo.findOne({ where: { id: recordId } });
    
    if (!record) {
      throw new Error('Travel Rule record not found');
    }

    // In production, this would integrate with TRISA, Sygna, or other Travel Rule protocols
    // For now, simulate verification
    const verified = true; // Simulated verification
    
    if (verified) {
      record.verificationStatus = 'VERIFIED';
      await this.travelRuleRepo.save(record);
      this.logger.log(`Travel Rule record ${recordId} verified with VASP`);
    } else {
      record.verificationStatus = 'FAILED';
      await this.travelRuleRepo.save(record);
      this.logger.warn(`Travel Rule record ${recordId} verification failed`);
    }

    return verified;
  }

  /**
   * Get Travel Rule records for audit
   */
  async getTravelRuleRecords(filters: {
    startDate?: Date;
    endDate?: Date;
    status?: string;
    limit?: number;
  }): Promise<any[]> {
    const query = this.travelRuleRepo.createQueryBuilder('tr');
    
    if (filters.startDate) {
      query.andWhere('tr.timestamp >= :startDate', { startDate: filters.startDate });
    }
    
    if (filters.endDate) {
      query.andWhere('tr.timestamp <= :endDate', { endDate: filters.endDate });
    }
    
    if (filters.status) {
      query.andWhere('tr.status = :status', { status: filters.status });
    }
    
    return query
      .orderBy('tr.timestamp', 'DESC')
      .limit(filters.limit || 100)
      .getMany();
  }

  /**
   * Generate Travel Rule report for regulators
   */
  async generateTravelRuleReport(period: { start: Date; end: Date }): Promise<{
    totalTransfers: number;
    compliantTransfers: number;
    nonCompliantTransfers: number;
    exemptedTransfers: number;
    averageAmount: number;
    records: any[];
  }> {
    const records = await this.getTravelRuleRecords({
      startDate: period.start,
      endDate: period.end,
    });

    const totalTransfers = records.length;
    const compliantTransfers = records.filter(r => r.status === 'COMPLIANT').length;
    const nonCompliantTransfers = records.filter(r => r.status === 'NON_COMPLIANT').length;
    const exemptedTransfers = records.filter(r => r.status === 'EXEMPTED').length;
    
    const averageAmount = records.reduce((sum, r) => sum + r.amountUsdCents, 0) / totalTransfers;

    return {
      totalTransfers,
      compliantTransfers,
      nonCompliantTransfers,
      exemptedTransfers,
      averageAmount,
      records,
    };
  }
}
