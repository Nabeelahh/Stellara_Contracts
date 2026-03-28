import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

export interface VersionMetrics {
  version: string;
  requestCount: number;
  errorCount: number;
  averageResponseTime: number;
  lastAccess: Date;
}

export interface MigrationStats {
  fromVersion: string;
  toVersion: string;
  migratedUsers: number;
  migrationDate: Date;
  successRate: number;
}

@Injectable()
export class ApiVersioningService {
  private readonly logger = new Logger(ApiVersioningService.name);
  private versionMetrics: Map<string, VersionMetrics> = new Map();
  private migrationStats: MigrationStats[] = [];

  constructor() {
    this.initializeMetrics();
  }

  private initializeMetrics(): void {
    // Initialize metrics for known versions
    this.versionMetrics.set('1', {
      version: '1',
      requestCount: 0,
      errorCount: 0,
      averageResponseTime: 0,
      lastAccess: new Date(),
    });

    this.versionMetrics.set('2', {
      version: '2',
      requestCount: 0,
      errorCount: 0,
      averageResponseTime: 0,
      lastAccess: new Date(),
    });
  }

  recordRequest(version: string, responseTime: number, isError: boolean = false): void {
    const metrics = this.versionMetrics.get(version);
    if (!metrics) {
      this.logger.warn(`No metrics found for version ${version}`);
      return;
    }

    metrics.requestCount++;
    if (isError) {
      metrics.errorCount++;
    }

    // Update average response time
    metrics.averageResponseTime =
      (metrics.averageResponseTime * (metrics.requestCount - 1) + responseTime) /
      metrics.requestCount;

    metrics.lastAccess = new Date();

    this.versionMetrics.set(version, metrics);
  }

  getVersionMetrics(version?: string): VersionMetrics | Map<string, VersionMetrics> {
    if (version) {
      return this.versionMetrics.get(version);
    }
    return this.versionMetrics;
  }

  getDeprecatedVersions(): string[] {
    return ['1']; // Version 1 is deprecated
  }

  getLatestVersion(): string {
    return '2';
  }

  getSunsetDate(version: string): Date | null {
    const sunsetDates = {
      '1': new Date('2024-06-01'),
      '2': null, // Latest version has no sunset date
    };
    return sunsetDates[version] || null;
  }

  getMigrationGuide(version: string): string | null {
    const migrationGuides = {
      '1': 'https://docs.stellara.io/migration/v1-to-v2',
      '2': null, // Latest version has no migration guide
    };
    return migrationGuides[version] || null;
  }

  recordMigration(stats: Omit<MigrationStats, 'migrationDate'>): void {
    const migration: MigrationStats = {
      ...stats,
      migrationDate: new Date(),
    };

    this.migrationStats.push(migration);
    this.logger.log(`Migration recorded: ${stats.fromVersion} -> ${stats.toVersion}`);
  }

  getMigrationStats(limit: number = 10): MigrationStats[] {
    return this.migrationStats
      .sort((a, b) => b.migrationDate.getTime() - a.migrationDate.getTime())
      .slice(0, limit);
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  generateDailyReport(): void {
    const report = this.generateUsageReport();
    this.logger.log('Daily API Version Usage Report:', report);
  }

  private generateUsageReport(): any {
    const totalRequests = Array.from(this.versionMetrics.values()).reduce(
      (sum, metrics) => sum + metrics.requestCount,
      0,
    );

    const totalErrors = Array.from(this.versionMetrics.values()).reduce(
      (sum, metrics) => sum + metrics.errorCount,
      0,
    );

    const versionUsage = Array.from(this.versionMetrics.entries()).map(([version, metrics]) => ({
      version,
      requests: metrics.requestCount,
      errors: metrics.errorCount,
      errorRate: metrics.requestCount > 0 ? (metrics.errorCount / metrics.requestCount) * 100 : 0,
      averageResponseTime: metrics.averageResponseTime,
      lastAccess: metrics.lastAccess,
    }));

    return {
      date: new Date().toISOString().split('T')[0],
      totalRequests,
      totalErrors,
      overallErrorRate: totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0,
      versionUsage,
      deprecatedVersions: this.getDeprecatedVersions(),
      recommendations: this.generateRecommendations(),
    };
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    const v1Metrics = this.versionMetrics.get('1');
    const v2Metrics = this.versionMetrics.get('2');

    if (v1Metrics && v1Metrics.requestCount > 0) {
      recommendations.push(`Consider migrating ${v1Metrics.requestCount} users from v1 to v2`);
    }

    if (v2Metrics && v2Metrics.errorCount > v2Metrics.requestCount * 0.05) {
      recommendations.push('v2 error rate is above 5%, investigate issues');
    }

    const deprecatedVersions = this.getDeprecatedVersions();
    if (deprecatedVersions.length > 0) {
      recommendations.push(`Plan sunset for deprecated versions: ${deprecatedVersions.join(', ')}`);
    }

    return recommendations;
  }

  isVersionSupported(version: string): boolean {
    const supportedVersions = ['1', '2'];
    return supportedVersions.includes(version);
  }

  getVersionCompatibility(version: string): {
    isDeprecated: boolean;
    sunsetDate?: Date;
    migrationGuide?: string;
    recommendedVersion: string;
  } {
    const isDeprecated = this.getDeprecatedVersions().includes(version);
    const sunsetDate = this.getSunsetDate(version);
    const migrationGuide = this.getMigrationGuide(version);
    const recommendedVersion = isDeprecated ? this.getLatestVersion() : version;

    return {
      isDeprecated,
      sunsetDate,
      migrationGuide,
      recommendedVersion,
    };
  }
}
