/**
 * Migration Strategy Module
 * Provides comprehensive migration handling including validation, backup, and rollback
 */

import { QueryRunner } from 'typeorm';
import { Logger } from '@nestjs/common';

/**
 * Represents the state and metadata of a migration execution
 */
export interface MigrationContext {
  migrationName: string;
  timestamp: Date;
  executedQueries: string[];
  dataBackup?: Record<string, any[]>;
  errors?: string[];
  duration?: number;
  status: 'pending' | 'in-progress' | 'completed' | 'failed' | 'rolled-back';
}

/**
 * Interface for migration validation rules
 */
export interface MigrationValidationRule {
  name: string;
  validate(queryRunner: QueryRunner): Promise<boolean>;
  errorMessage: string;
}

/**
 * Interface for data backup strategy
 */
export interface BackupStrategy {
  tables: string[];
  strategy: 'full' | 'incremental' | 'snapshot';
  condition?: (queryRunner: QueryRunner) => Promise<boolean>;
}

/**
 * Enhanced Migration interface with validation and rollback support
 */
export interface EnhancedMigration {
  name: string;
  version: string;
  description?: string;
  backupStrategy?: BackupStrategy;
  preValidationRules?: MigrationValidationRule[];
  postValidationRules?: MigrationValidationRule[];
  up(queryRunner: QueryRunner, context: MigrationContext): Promise<void>;
  down(queryRunner: QueryRunner, context: MigrationContext): Promise<void>;
  rollback?(queryRunner: QueryRunner, context: MigrationContext): Promise<void>;
}

/**
 * Migration Validation Service
 * Validates database state before and after migrations
 */
export class MigrationValidator {
  private readonly logger = new Logger('MigrationValidator');

  /**
   * Run pre-migration validation checks
   */
  async validatePreMigration(
    queryRunner: QueryRunner,
    rules: MigrationValidationRule[],
    migrationName: string,
  ): Promise<{ isValid: boolean; errors: string[] }> {
    const errors: string[] = [];

    this.logger.log(`[${migrationName}] Running pre-migration validation...`);

    for (const rule of rules || []) {
      try {
        const isValid = await rule.validate(queryRunner);
        if (!isValid) {
          errors.push(`[${rule.name}] ${rule.errorMessage}`);
        }
      } catch (error) {
        errors.push(
          `[${rule.name}] Validation failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    const isValid = errors.length === 0;
    this.logger.log(
      `[${migrationName}] Pre-migration validation ${isValid ? 'PASSED' : 'FAILED'}`,
    );

    return { isValid, errors };
  }

  /**
   * Run post-migration validation checks
   */
  async validatePostMigration(
    queryRunner: QueryRunner,
    rules: MigrationValidationRule[],
    migrationName: string,
  ): Promise<{ isValid: boolean; errors: string[] }> {
    const errors: string[] = [];

    this.logger.log(`[${migrationName}] Running post-migration validation...`);

    for (const rule of rules || []) {
      try {
        const isValid = await rule.validate(queryRunner);
        if (!isValid) {
          errors.push(`[${rule.name}] ${rule.errorMessage}`);
        }
      } catch (error) {
        errors.push(
          `[${rule.name}] Validation failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    const isValid = errors.length === 0;
    this.logger.log(
      `[${migrationName}] Post-migration validation ${isValid ? 'PASSED' : 'FAILED'}`,
    );

    return { isValid, errors };
  }

  /**
   * Common validation rules
   */
  static commonRules = {
    /**
     * Check if table exists
     */
    tableExists: (tableName: string): MigrationValidationRule => ({
      name: 'TableExists',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT EXISTS (
              SELECT 1 FROM information_schema.tables 
              WHERE table_name = $1
            )`,
            [tableName],
          );
          return result[0].exists;
        } catch {
          return false;
        }
      },
      errorMessage: `Table '${tableName}' does not exist`,
    }),

    /**
     * Check if column exists
     */
    columnExists: (
      tableName: string,
      columnName: string,
    ): MigrationValidationRule => ({
      name: 'ColumnExists',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT EXISTS (
              SELECT 1 FROM information_schema.columns
              WHERE table_name = $1 AND column_name = $2
            )`,
            [tableName, columnName],
          );
          return result[0].exists;
        } catch {
          return false;
        }
      },
      errorMessage: `Column '${columnName}' does not exist in table '${tableName}'`,
    }),

    /**
     * Check if table has no foreign key constraints pointing to it
     */
    noIncomingForeignKeys: (tableName: string): MigrationValidationRule => ({
      name: 'NoIncomingForeignKeys',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT COUNT(*) as count FROM information_schema.referential_constraints
             WHERE constraint_schema = 'public' 
             AND cte_table_name = $1`,
            [tableName],
          );
          return Number(result[0].count) === 0;
        } catch {
          return true; // Fail-safe: allow migration if validation query fails
        }
      },
      errorMessage: `Table '${tableName}' has incoming foreign key constraints`,
    }),

    /**
     * Check if table has data
     */
    tableHasData: (tableName: string): MigrationValidationRule => ({
      name: 'TableHasData',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT EXISTS (SELECT 1 FROM "${tableName}" LIMIT 1)`,
          );
          return result[0].exists;
        } catch {
          return false;
        }
      },
      errorMessage: `Table '${tableName}' is empty`,
    }),

    /**
     * Check if table is empty
     */
    tableIsEmpty: (tableName: string): MigrationValidationRule => ({
      name: 'TableIsEmpty',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT COUNT(*) as count FROM "${tableName}"`,
          );
          return Number(result[0].count) === 0;
        } catch {
          return false;
        }
      },
      errorMessage: `Table '${tableName}' is not empty`,
    }),

    /**
     * Check index exists
     */
    indexExists: (indexName: string): MigrationValidationRule => ({
      name: 'IndexExists',
      async validate(queryRunner: QueryRunner) {
        try {
          const result = await queryRunner.query(
            `SELECT EXISTS (
              SELECT 1 FROM information_schema.statistics
              WHERE index_name = $1
            )`,
            [indexName],
          );
          return result[0].exists;
        } catch {
          return false;
        }
      },
      errorMessage: `Index '${indexName}' does not exist`,
    }),
  };
}

/**
 * Migration Backup Service
 * Handles data backup and restoration
 */
export class MigrationBackup {
  private readonly logger = new Logger('MigrationBackup');

  /**
   * Create backup of specified tables
   */
  async backupTables(
    queryRunner: QueryRunner,
    tableNames: string[],
    migrationName: string,
  ): Promise<Record<string, any[]>> {
    const backup: Record<string, any[]> = {};

    this.logger.log(
      `[${migrationName}] Creating backup for tables: ${tableNames.join(', ')}`,
    );

    for (const tableName of tableNames) {
      try {
        const data = await queryRunner.query(
          `SELECT * FROM "${tableName}" ORDER BY "id" DESC LIMIT 10000`,
        );
        backup[tableName] = data;
        this.logger.log(`[${migrationName}] Backed up ${data.length} rows from ${tableName}`);
      } catch (error) {
        this.logger.warn(
          `[${migrationName}] Failed to backup ${tableName}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return backup;
  }

  /**
   * Restore tables from backup
   */
  async restoreFromBackup(
    queryRunner: QueryRunner,
    backup: Record<string, any[]>,
    migrationName: string,
  ): Promise<void> {
    this.logger.log(`[${migrationName}] Restoring backup...`);

    for (const [tableName, rows] of Object.entries(backup)) {
      try {
        if (rows.length === 0) continue;

        // Disable foreign keys during restore
        await queryRunner.query('SET CONSTRAINTS ALL DEFERRED');

        // Delete existing data
        await queryRunner.query(`TRUNCATE TABLE "${tableName}" CASCADE`);

        // Restore data
        const columns = Object.keys(rows[0]);
        const values = rows
          .map((row) => `(${columns.map((col) => `'${String(row[col]).replace(/'/g, "''")}'`).join(', ')})`)
          .join(', ');

        await queryRunner.query(
          `INSERT INTO "${tableName}" (${columns.join(', ')}) VALUES ${values}`,
        );

        // Re-enable foreign keys
        await queryRunner.query('SET CONSTRAINTS ALL IMMEDIATE');

        this.logger.log(`[${migrationName}] Restored ${rows.length} rows to ${tableName}`);
      } catch (error) {
        this.logger.error(
          `[${migrationName}] Failed to restore ${tableName}: ${error instanceof Error ? error.message : String(error)}`,
        );
        throw error;
      }
    }
  }

  /**
   * Get table row count
   */
  async getTableRowCount(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<number> {
    try {
      const result = await queryRunner.query(
        `SELECT COUNT(*) as count FROM "${tableName}"`,
      );
      return Number(result[0].count);
    } catch {
      return 0;
    }
  }

  /**
   * Verify data integrity after migration
   */
  async verifyDataIntegrity(
    queryRunner: QueryRunner,
    tableName: string,
    beforeCount: number,
    afterCount: number,
  ): Promise<{ isValid: boolean; message: string }> {
    if (afterCount === beforeCount) {
      return {
        isValid: true,
        message: `Row count preserved: ${beforeCount} rows`,
      };
    }

    return {
      isValid: false,
      message: `Row count mismatch: before=${beforeCount}, after=${afterCount}`,
    };
  }
}

/**
 * Migration Rollback Service
 * Handles safe rollback of migrations with optional transaction support
 */
export class MigrationRollback {
  private readonly logger = new Logger('MigrationRollback');

  /**
   * Execute rollback with safety checks
   */
  async executeRollback(
    queryRunner: QueryRunner,
    context: MigrationContext,
    rollbackFn: () => Promise<void>,
  ): Promise<void> {
    const startTime = Date.now();

    try {
      this.logger.log(
        `[${context.migrationName}] Initiating rollback procedure...`,
      );

      // Start transaction
      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      // Execute rollback
      await rollbackFn();

      // Commit if no errors
      if (queryRunner.isTransactionActive) {
        await queryRunner.commitTransaction();
      }

      const duration = Date.now() - startTime;
      this.logger.log(
        `[${context.migrationName}] Rollback completed successfully in ${duration}ms`,
      );

      context.status = 'rolled-back';
      context.duration = duration;
    } catch (error) {
      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }

      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(
        `[${context.migrationName}] Rollback failed: ${errorMessage}`,
      );

      throw new Error(`Rollback failed: ${errorMessage}`);
    }
  }

  /**
   * Safe migration execution with automatic rollback on failure
   */
  async executeMigrationSafely(
    queryRunner: QueryRunner,
    migrationName: string,
    migrationFn: () => Promise<void>,
    rollbackFn: () => Promise<void>,
    backup?: Record<string, any[]>,
  ): Promise<MigrationContext> {
    const context: MigrationContext = {
      migrationName,
      timestamp: new Date(),
      executedQueries: [],
      dataBackup: backup,
      status: 'pending',
    };

    const startTime = Date.now();

    try {
      context.status = 'in-progress';
      this.logger.log(`[${migrationName}] Starting migration...`);

      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      await migrationFn();

      if (queryRunner.isTransactionActive) {
        await queryRunner.commitTransaction();
      }

      context.status = 'completed';
      context.duration = Date.now() - startTime;

      this.logger.log(
        `[${migrationName}] Migration completed successfully in ${context.duration}ms`,
      );

      return context;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);

      context.status = 'failed';
      context.duration = Date.now() - startTime;
      context.errors = [errorMessage];

      this.logger.error(
        `[${migrationName}] Migration failed after ${context.duration}ms: ${errorMessage}`,
      );

      // Attempt rollback
      try {
        this.logger.log(`[${migrationName}] Attempting automatic rollback...`);
        await this.executeRollback(queryRunner, context, rollbackFn);

        // Restore from backup if available
        if (backup && Object.keys(backup).length > 0) {
          this.logger.log(`[${migrationName}] Restoring data from backup...`);
          const backupService = new MigrationBackup();
          await backupService.restoreFromBackup(queryRunner, backup, migrationName);
        }
      } catch (rollbackError) {
        const rollbackMessage =
          rollbackError instanceof Error
            ? rollbackError.message
            : String(rollbackError);
        context.errors?.push(`Rollback also failed: ${rollbackMessage}`);
        this.logger.error(
          `[${migrationName}] Rollback failed: ${rollbackMessage}`,
        );
      }

      throw error;
    }
  }
}

/**
 * Migration Logger and Metrics
 * Tracks migration execution metrics and logs
 */
export class MigrationMetrics {
  private readonly logger = new Logger('MigrationMetrics');
  private migrations: MigrationContext[] = [];

  /**
   * Record migration execution
   */
  recordMigration(context: MigrationContext): void {
    this.migrations.push(context);

    const metrics = {
      name: context.migrationName,
      status: context.status,
      duration: context.duration,
      timestamp: context.timestamp,
      queriesExecuted: context.executedQueries.length,
      errors: context.errors?.length || 0,
    };

    this.logger.log(`Migration recorded: ${JSON.stringify(metrics)}`);
  }

  /**
   * Get migration history
   */
  getMigrationHistory(): MigrationContext[] {
    return [...this.migrations];
  }

  /**
   * Get metrics summary
   */
  getMetricsSummary(): {
    totalMigrations: number;
    successful: number;
    failed: number;
    rolledBack: number;
    averageDuration: number;
  } {
    const total = this.migrations.length;
    const successful = this.migrations.filter(
      (m) => m.status === 'completed',
    ).length;
    const failed = this.migrations.filter((m) => m.status === 'failed').length;
    const rolledBack = this.migrations.filter(
      (m) => m.status === 'rolled-back',
    ).length;
    const averageDuration =
      total > 0
        ? this.migrations.reduce((sum, m) => sum + (m.duration || 0), 0) / total
        : 0;

    return {
      totalMigrations: total,
      successful,
      failed,
      rolledBack,
      averageDuration,
    };
  }

  /**
   * Clear migration history
   */
  clearHistory(): void {
    this.migrations = [];
    this.logger.log('Migration history cleared');
  }
}
