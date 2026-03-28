import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { SanctionsListType, RiskLevel } from '../dto/compliance.dto';

export interface SanctionedEntity {
  id: string;
  name: string;
  type: 'INDIVIDUAL' | 'ENTITY' | 'VESSEL' | 'AIRCRAFT';
  programs: string[];
  listType: SanctionsListType;
  aliases: string[];
  dateOfBirth?: string;
  placeOfBirth?: string;
  nationality?: string;
  passportNumber?: string;
  nationalIdNumber?: string;
  addresses: string[];
  walletAddresses: string[];
  vessels: string[];
  aircrafts: string[];
  remarks: string;
  sourceListUrl: string;
  lastUpdated: Date;
}

@Injectable()
export class SanctionsScreeningService {
  private readonly logger = new Logger(SanctionsScreeningService.name);
  private sanctionsCache: Map<string, SanctionedEntity[]> = new Map();
  private lastCacheUpdate: Date | null = null;
  private readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  constructor(
    @InjectRepository('sanctions_list')
    private readonly sanctionsRepo: Repository<any>,
    private readonly dataSource: DataSource,
  ) {}

  async onModuleInit() {
    await this.loadSanctionsLists();
  }

  /**
   * Load all sanctions lists from database or external APIs
   */
  async loadSanctionsLists(): Promise<void> {
    try {
      this.logger.log('Loading sanctions lists from database...');
      
      // Load from database (populated by scheduled job)
      const sanctions = await this.sanctionsRepo.find({
        where: { isActive: true },
        order: { lastUpdated: 'DESC' },
      });

      // Group by list type
      const grouped = new Map<SanctionsListType, any[]>();
      sanctions.forEach((entity) => {
        const list = grouped.get(entity.listType as SanctionsListType) || [];
        list.push(entity);
        grouped.set(entity.listType as SanctionsListType, list);
      });

      // Store in cache for fast lookup
      this.sanctionsCache.set('ALL_SANCTIONS', sanctions);
      this.lastCacheUpdate = new Date();

      this.logger.log(`Loaded ${sanctions.length} sanctioned entities from ${grouped.size} lists`);
    } catch (error) {
      this.logger.error('Failed to load sanctions lists:', error);
      throw error;
    }
  }

  /**
   * Screen a counterparty against all 15+ sanctions lists
   */
  async screenCounterparty(data: {
    name?: string;
    dateOfBirth?: string;
    country?: string;
    walletAddress?: string;
    nationalId?: string;
    registrationNumber?: string;
  }): Promise<{
    isMatch: boolean;
    matches: Array<{
      entity: SanctionedEntity;
      matchScore: number;
      matchReasons: string[];
    }>;
    riskLevel: RiskLevel;
  }> {
    const matches: Array<{
      entity: SanctionedEntity;
      matchScore: number;
      matchReasons: string[];
    }> = [];

    const allSanctions = this.sanctionsCache.get('ALL_SANCTIONS') || [];

    // Name matching (fuzzy match with threshold)
    if (data.name) {
      const normalizedName = this.normalizeString(data.name);
      
      for (const entity of allSanctions) {
        let matchScore = 0;
        const matchReasons: string[] = [];

        // Check primary name
        const entityName = this.normalizeString(entity.name);
        const nameSimilarity = this.calculateStringSimilarity(normalizedName, entityName);
        
        if (nameSimilarity >= 0.85) {
          matchScore += 50;
          matchReasons.push(`Name match: ${nameSimilarity.toFixed(2)}`);
        }

        // Check aliases
        for (const alias of entity.aliases || []) {
          const aliasSimilarity = this.calculateStringSimilarity(normalizedName, this.normalizeString(alias));
          if (aliasSimilarity >= 0.85) {
            matchScore += 40;
            matchReasons.push(`Alias match: ${alias} (${aliasSimilarity.toFixed(2)})`);
            break;
          }
        }

        // Check DOB match
        if (data.dateOfBirth && entity.dateOfBirth) {
          if (this.datesMatch(data.dateOfBirth, entity.dateOfBirth)) {
            matchScore += 30;
            matchReasons.push('Date of birth match');
          }
        }

        // Check nationality/country
        if (data.country && entity.nationality) {
          if (this.normalizeString(data.country) === this.normalizeString(entity.nationality)) {
            matchScore += 15;
            matchReasons.push('Nationality match');
          }
        }

        // Check wallet address
        if (data.walletAddress && entity.walletAddresses?.length > 0) {
          const walletMatch = entity.walletAddresses.some(
            (w) => w.toLowerCase() === data.walletAddress!.toLowerCase(),
          );
          if (walletMatch) {
            matchScore += 100; // Critical match
            matchReasons.push('Wallet address match - CRITICAL');
          }
        }

        // Check national ID/passport
        if (data.nationalId && (entity.passportNumber || entity.nationalIdNumber)) {
          const idMatch = 
            (entity.passportNumber && data.nationalId === entity.passportNumber) ||
            (entity.nationalIdNumber && data.nationalId === entity.nationalIdNumber);
          if (idMatch) {
            matchScore += 100; // Critical match
            matchReasons.push('National ID/Passport match - CRITICAL');
          }
        }

        if (matchScore >= 40) { // Minimum threshold for potential match
          matches.push({
            entity,
            matchScore,
            matchReasons,
          });
        }
      }
    }

    // Sort by match score descending
    matches.sort((a, b) => b.matchScore - a.matchScore);

    // Determine overall risk level
    let riskLevel = RiskLevel.MINIMAL;
    if (matches.some(m => m.matchScore >= 100)) {
      riskLevel = RiskLevel.CRITICAL;
    } else if (matches.some(m => m.matchScore >= 70)) {
      riskLevel = RiskLevel.HIGH;
    } else if (matches.some(m => m.matchScore >= 50)) {
      riskLevel = RiskLevel.MEDIUM;
    } else if (matches.length > 0) {
      riskLevel = RiskLevel.LOW;
    }

    return {
      isMatch: matches.length > 0 && matches[0].matchScore >= 40,
      matches,
      riskLevel,
    };
  }

  /**
   * Check specifically against OFAC SDN list
   */
  async checkOFACSDN(name: string): Promise<boolean> {
    const result = await this.screenCounterparty({ name });
    return result.matches.some(m => m.entity.listType === SanctionsListType.OFAC);
  }

  /**
   * Normalize string for comparison
   */
  private normalizeString(str: string): string {
    return str
      .toLowerCase()
      .trim()
      .replace(/[^\w\s]/gi, '')
      .replace(/\s+/g, ' ');
  }

  /**
   * Calculate Levenshtein distance for string similarity
   */
  private calculateStringSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) return 1.0;
    
    const editDistance = this.levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1,
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  /**
   * Check if dates match (handles various formats)
   */
  private datesMatch(date1: string, date2: string): boolean {
    const d1 = new Date(date1);
    const d2 = new Date(date2);
    return (
      d1.getFullYear() === d2.getFullYear() &&
      d1.getMonth() === d2.getMonth() &&
      d1.getDate() === d2.getDate()
    );
  }

  /**
   * Get statistics about loaded sanctions lists
   */
  getSanctionsStats(): { totalEntities: number; byList: Record<string, number> } {
    const allSanctions = this.sanctionsCache.get('ALL_SANCTIONS') || [];
    const byList: Record<string, number> = {};
    
    allSanctions.forEach((entity) => {
      const listType = entity.listType as string;
      byList[listType] = (byList[listType] || 0) + 1;
    });
    
    return {
      totalEntities: allSanctions.length,
      byList,
    };
  }
}
