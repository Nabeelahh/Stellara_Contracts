import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { PostgresService } from '../database/postgres.service';

interface QueryPattern {
  queryId: string;
  query: string;
  calls: number;
  totalExecTime: number;
  meanExecTime: number;
  table?: string;
  filterColumns: string[];
}

interface IndexRecommendation {
  table: string;
  columns: string[];
  reason: string;
  estimatedImpact: string;
}

interface IndexAnalysisReport {
  generatedAt: string;
  extensionEnabled: boolean;
  queryPatterns: QueryPattern[];
  unusedIndexes: any[];
  usageStats: any[];
  recommendations: IndexRecommendation[];
  performanceMetrics: {
    analyzedQueries: number;
    slowQueries: number;
    totalExecTimeMs: number;
    estimatedImprovementScore: number;
  };
}

@Injectable()
export class IndexAnalysisService implements OnModuleInit {
  private readonly logger = new Logger(IndexAnalysisService.name);
  private readonly reportsDir = path.resolve(
    process.cwd(),
    process.env.INDEX_ANALYSIS_REPORT_DIR || 'prisma/index-reports',
  );
  private readonly migrationsDir = path.resolve(
    process.cwd(),
    process.env.INDEX_ANALYSIS_MIGRATIONS_DIR || 'prisma/generated-index-migrations',
  );
  private extensionEnabled = false;

  constructor(private readonly postgres: PostgresService) {}

  async onModuleInit(): Promise<void> {
    await fs.mkdir(this.reportsDir, { recursive: true });
    await fs.mkdir(this.migrationsDir, { recursive: true });
    await this.ensurePgStatStatements();
  }

  async ensurePgStatStatements(): Promise<boolean> {
    try {
      await this.postgres.execute('CREATE EXTENSION IF NOT EXISTS pg_stat_statements');
    } catch (error) {
      this.logger.warn(
        `Unable to create pg_stat_statements extension automatically: ${error.message}`,
      );
    }

    try {
      const result = await this.postgres.query<{ enabled: boolean }>(`
        SELECT EXISTS (
          SELECT 1
          FROM pg_extension
          WHERE extname = 'pg_stat_statements'
        ) AS enabled
      `);
      this.extensionEnabled = Boolean(result?.[0]?.enabled);
    } catch (error) {
      this.logger.warn(`Unable to verify pg_stat_statements extension: ${error.message}`);
      this.extensionEnabled = false;
    }

    return this.extensionEnabled;
  }

  @Cron('0 0 * * 0')
  async generateWeeklyIndexAnalysis(): Promise<void> {
    await this.generateReport();
  }

  async generateReport(): Promise<IndexAnalysisReport> {
    const queryPatterns = await this.collectQueryPatterns();
    const unusedIndexes = await this.collectUnusedIndexes();
    const usageStats = await this.collectIndexUsageStats();
    const recommendations = this.buildRecommendations(queryPatterns, usageStats);
    const performanceMetrics = this.buildPerformanceMetrics(queryPatterns, recommendations);

    const report: IndexAnalysisReport = {
      generatedAt: new Date().toISOString(),
      extensionEnabled: this.extensionEnabled,
      queryPatterns,
      unusedIndexes,
      usageStats,
      recommendations,
      performanceMetrics,
    };

    const filePath = path.join(
      this.reportsDir,
      `weekly-index-analysis-${this.formatTimestampForFile(new Date())}.json`,
    );

    await fs.writeFile(filePath, JSON.stringify(report, null, 2), 'utf8');

    return report;
  }

  async getLatestReport(): Promise<IndexAnalysisReport | null> {
    const files = await fs.readdir(this.reportsDir).catch(() => []);
    const latest = files
      .filter((file) => file.endsWith('.json'))
      .sort()
      .reverse()[0];

    if (!latest) {
      return null;
    }

    const content = await fs.readFile(path.join(this.reportsDir, latest), 'utf8');
    return JSON.parse(content) as IndexAnalysisReport;
  }

  async generateMigrationScript(): Promise<{ path: string; recommendations: number }> {
    const report = (await this.getLatestReport()) || (await this.generateReport());
    const statements = report.recommendations.map((recommendation) => {
      const name = this.buildIndexName(recommendation.table, recommendation.columns);
      return `CREATE INDEX CONCURRENTLY IF NOT EXISTS ${this.quoteIdentifier(name)} ON ${this.quoteQualifiedIdentifier(recommendation.table)} (${recommendation.columns.map((column) => this.quoteIdentifier(column)).join(', ')});`;
    });

    const filePath = path.join(
      this.migrationsDir,
      `${this.formatTimestampForFile(new Date())}_recommended_indexes.sql`,
    );

    await fs.writeFile(filePath, statements.join('\n') + (statements.length ? '\n' : ''), 'utf8');

    return {
      path: filePath,
      recommendations: report.recommendations.length,
    };
  }

  async getStatus(): Promise<any> {
    const latestReport = await this.getLatestReport();

    return {
      extensionEnabled: this.extensionEnabled,
      reportsDirectory: this.reportsDir,
      migrationsDirectory: this.migrationsDir,
      latestReportGeneratedAt: latestReport?.generatedAt || null,
      recommendationCount: latestReport?.recommendations.length || 0,
    };
  }

  private async collectQueryPatterns(): Promise<QueryPattern[]> {
    if (!this.extensionEnabled) {
      return [];
    }

    const rows = await this.postgres.query<{
      query_id: string;
      query: string;
      calls: number;
      total_exec_time: number;
      mean_exec_time: number;
    }>(`
      SELECT
        queryid::text AS query_id,
        query,
        calls,
        total_exec_time,
        mean_exec_time
      FROM pg_stat_statements
      WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
      ORDER BY total_exec_time DESC
      LIMIT 50
    `);

    return rows.map((row) => {
      const parsed = this.extractQueryDetails(row.query);
      return {
        queryId: row.query_id,
        query: row.query,
        calls: Number(row.calls),
        totalExecTime: Number(row.total_exec_time),
        meanExecTime: Number(row.mean_exec_time),
        table: parsed.table,
        filterColumns: parsed.filterColumns,
      };
    });
  }

  private async collectUnusedIndexes(): Promise<any[]> {
    return this.postgres.query(`
      SELECT
        schemaname,
        relname AS table_name,
        indexrelname AS index_name,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch,
        pg_size_pretty(pg_relation_size(indexrelid)) AS size
      FROM pg_stat_user_indexes
      WHERE idx_scan = 0
        AND indexrelname NOT LIKE '%_pkey'
      ORDER BY pg_relation_size(indexrelid) DESC
    `);
  }

  private async collectIndexUsageStats(): Promise<any[]> {
    return this.postgres.query(`
      SELECT
        schemaname,
        relname AS table_name,
        indexrelname AS index_name,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch
      FROM pg_stat_user_indexes
      ORDER BY idx_scan DESC, idx_tup_read DESC
    `);
  }

  private buildRecommendations(patterns: QueryPattern[], usageStats: any[]): IndexRecommendation[] {
    const existingIndexNames = new Set(
      usageStats.map((stat) => String(stat.index_name || '').toLowerCase()),
    );
    const recommendations = new Map<string, IndexRecommendation>();

    for (const pattern of patterns) {
      if (!pattern.table || pattern.filterColumns.length === 0) {
        continue;
      }

      const normalizedColumns = Array.from(new Set(pattern.filterColumns));
      const key = `${pattern.table}:${normalizedColumns.join(',')}`;
      const syntheticIndexName = this.buildIndexName(
        pattern.table,
        normalizedColumns,
      ).toLowerCase();
      if (existingIndexNames.has(syntheticIndexName) || recommendations.has(key)) {
        continue;
      }

      recommendations.set(key, {
        table: pattern.table,
        columns: normalizedColumns,
        reason:
          normalizedColumns.length > 1
            ? 'Frequent multi-column filter pattern detected'
            : 'Frequent filter without obvious supporting index',
        estimatedImpact:
          pattern.meanExecTime > 100 ? 'high' : pattern.meanExecTime > 25 ? 'medium' : 'low',
      });
    }

    return Array.from(recommendations.values());
  }

  private buildPerformanceMetrics(
    patterns: QueryPattern[],
    recommendations: IndexRecommendation[],
  ) {
    const totalExecTimeMs = patterns.reduce((total, pattern) => total + pattern.totalExecTime, 0);
    const slowQueries = patterns.filter((pattern) => pattern.meanExecTime >= 50).length;

    return {
      analyzedQueries: patterns.length,
      slowQueries,
      totalExecTimeMs,
      estimatedImprovementScore: Math.min(100, recommendations.length * 10 + slowQueries * 5),
    };
  }

  private extractQueryDetails(query: string): {
    table?: string;
    filterColumns: string[];
  } {
    const normalized = query.replace(/\s+/g, ' ').trim();
    const fromMatch = normalized.match(/\bfrom\s+("?[\w.]+"?)/i);
    const whereMatch = normalized.match(
      /\bwhere\b\s+(.+?)(?:\border by\b|\bgroup by\b|\blimit\b|$)/i,
    );

    const filterColumns = new Set<string>();
    const filterClause = whereMatch?.[1] || '';
    const columnMatcher = /([a-z_][\w.]*?)\s*(=|>|<|>=|<=|like|ilike|in|between)/gi;

    let match: RegExpExecArray | null = null;
    while ((match = columnMatcher.exec(filterClause))) {
      const column = match[1].split('.').pop();
      if (column) {
        filterColumns.add(column);
      }
    }

    return {
      table: fromMatch?.[1]?.replace(/"/g, ''),
      filterColumns: Array.from(filterColumns),
    };
  }

  private formatTimestampForFile(date: Date): string {
    return date.toISOString().replace(/[:.]/g, '-');
  }

  private buildIndexName(table: string, columns: string[]): string {
    return `idx_${this.sanitizeIdentifierFragment(table)}_${columns
      .map((column) => this.sanitizeIdentifierFragment(column))
      .join('_')}`;
  }

  private quoteQualifiedIdentifier(value: string): string {
    return value
      .split('.')
      .map((part) => this.quoteIdentifier(part))
      .join('.');
  }

  private quoteIdentifier(value: string): string {
    const normalized = value.replace(/^"+|"+$/g, '');
    return `"${normalized.replace(/"/g, '""')}"`;
  }

  private sanitizeIdentifierFragment(value: string): string {
    return value
      .replace(/^"+|"+$/g, '')
      .replace(/[^a-zA-Z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .toLowerCase();
  }
}
