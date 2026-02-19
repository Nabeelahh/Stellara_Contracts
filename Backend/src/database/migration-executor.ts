/**
 * Migration Executor
 * Orchestrates the complete migration lifecycle with validation and rollback support
 */

import { Logger } from '@nestjs/common';
import { QueryRunner } from 'typeorm';
import {
  MigrationContext,
  EnhancedMigration,
  MigrationValidator,
  MigrationBackup,
  MigrationRollback,
  MigrationMetrics,
} from './migration-strategy';

/**
 * Main migration executor class
 * Handles the complete migration lifecycle
 */
export class MigrationExecutor {
  private readonly logger = new Logger('MigrationExecutor');
  private readonly validator = new MigrationValidator();
  private readonly backupService = new MigrationBackup();
  private readonly rollbackService = new MigrationRollback();
  private readonly metrics = new MigrationMetrics();

  /**
   * Execute a single migration with full safety checks
   */
  async executeMigration(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
    isDryRun: boolean = false,
  ): Promise<MigrationContext> {
    const context: MigrationContext = {
      migrationName: migration.name,
      timestamp: new Date(),
      executedQueries: [],
      status: 'pending',
    };

    const startTime = Date.now();

    try {
      this.logger.log(
        `========== MIGRATION: ${migration.name} ==========`,
      );
      this.logger.log(`Description: ${migration.description || 'N/A'}`);
      this.logger.log(`Version: ${migration.version}`);
      this.logger.log(`Dry Run: ${isDryRun}`);

      // Step 1: Pre-migration validation
      if (migration.preValidationRules && migration.preValidationRules.length > 0) {
        this.logger.log('Step 1: Running pre-migration validation checks...');
        const validationResult = await this.validator.validatePreMigration(
          queryRunner,
          migration.preValidationRules,
          migration.name,
        );

        if (!validationResult.isValid) {
          throw new Error(
            `Pre-migration validation failed:\n${validationResult.errors.join('\n')}`,
          );
        }
      }

      // Step 2: Create backup
      let backup: Record<string, any[]> = {};
      if (migration.backupStrategy) {
        this.logger.log('Step 2: Creating data backup...');
        backup = await this.backupService.backupTables(
          queryRunner,
          migration.backupStrategy.tables,
          migration.name,
        );

        for (const [table, rows] of Object.entries(backup)) {
          this.logger.log(`  ✓ Backed up ${rows.length} rows from ${table}`);
        }
      }

      // Step 3: Execute migration
      this.logger.log('Step 3: Executing migration...');

      if (isDryRun) {
        this.logger.log('DRY RUN MODE: Skipping actual migration execution');
        context.status = 'completed';
      } else {
        // Start transaction
        if (!queryRunner.isTransactionActive) {
          await queryRunner.startTransaction();
        }

        try {
          await migration.up(queryRunner, context);

          if (queryRunner.isTransactionActive) {
            await queryRunner.commitTransaction();
          }

          this.logger.log('Migration executed successfully');
        } catch (error) {
          if (queryRunner.isTransactionActive) {
            await queryRunner.rollbackTransaction();
          }

          throw error;
        }
      }

      // Step 4: Post-migration validation
      if (migration.postValidationRules && migration.postValidationRules.length > 0) {
        this.logger.log('Step 4: Running post-migration validation checks...');
        const validationResult = await this.validator.validatePostMigration(
          queryRunner,
          migration.postValidationRules,
          migration.name,
        );

        if (!validationResult.isValid) {
          throw new Error(
            `Post-migration validation failed:\n${validationResult.errors.join('\n')}`,
          );
        }
      }

      context.status = 'completed';
      context.duration = Date.now() - startTime;
      context.dataBackup = backup;

      this.logger.log(`✅ Migration completed in ${context.duration}ms`);
      this.logger.log('===========================================\n');

      this.metrics.recordMigration(context);
      return context;
    } catch (error) {
      context.status = 'failed';
      context.duration = Date.now() - startTime;
      context.errors = [
        error instanceof Error ? error.message : String(error),
      ];

      this.logger.error(
        `❌ Migration failed after ${context.duration}ms`,
      );
      this.logger.error(`Error: ${context.errors[0]}`);

      // Attempt rollback if migration has rollback function
      if (migration.rollback) {
        try {
          this.logger.log('Attempting rollback...');
          await migration.rollback(queryRunner, context);
          context.status = 'rolled-back';
          this.logger.log('Rollback completed successfully');
        } catch (rollbackError) {
          const rollbackMsg =
            rollbackError instanceof Error
              ? rollbackError.message
              : String(rollbackError);
          context.errors?.push(`Rollback failed: ${rollbackMsg}`);
          this.logger.error(`Rollback failed: ${rollbackMsg}`);
        }
      }

      this.logger.log('===========================================\n');
      this.metrics.recordMigration(context);
      throw error;
    }
  }

  /**
   * Execute multiple migrations in sequence
   */
  async executeMigrations(
    queryRunner: QueryRunner,
    migrations: EnhancedMigration[],
    isDryRun: boolean = false,
  ): Promise<MigrationContext[]> {
    const results: MigrationContext[] = [];
    let allSuccessful = true;

    this.logger.log(
      `\n🚀 Starting migration batch (${migrations.length} migrations)`,
    );

    for (const migration of migrations) {
      try {
        const result = await this.executeMigration(queryRunner, migration, isDryRun);
        results.push(result);
      } catch (error) {
        allSuccessful = false;
        this.logger.error(`Migration ${migration.name} failed, stopping batch`);
        break;
      }
    }

    // Print summary
    this.printMigrationSummary(results, allSuccessful);

    return results;
  }

  /**
   * Rollback last migration
   */
  async rollbackLastMigration(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<void> {
    if (!migration.rollback) {
      throw new Error(`Migration ${migration.name} does not support rollback`);
    }

    this.logger.log(`\n⏮️  Rolling back migration: ${migration.name}`);

    const context: MigrationContext = {
      migrationName: migration.name,
      timestamp: new Date(),
      executedQueries: [],
      status: 'in-progress',
    };

    const startTime = Date.now();

    try {
      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      await migration.rollback(queryRunner, context);

      if (queryRunner.isTransactionActive) {
        await queryRunner.commitTransaction();
      }

      context.status = 'rolled-back';
      context.duration = Date.now() - startTime;

      this.logger.log(
        `✅ Rollback completed successfully in ${context.duration}ms`,
      );
    } catch (error) {
      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }

      const errorMsg =
        error instanceof Error ? error.message : String(error);
      this.logger.error(`Rollback failed: ${errorMsg}`);
      throw error;
    }
  }

  /**
   * Verify migration integrity
   */
  async verifyMigration(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<boolean> {
    if (!migration.postValidationRules) {
      this.logger.warn('No post-validation rules defined for verification');
      return true;
    }

    const result = await this.validator.validatePostMigration(
      queryRunner,
      migration.postValidationRules,
      migration.name,
    );

    return result.isValid;
  }

  /**
   * Get migration metrics
   */
  getMigrationMetrics() {
    return this.metrics.getMetricsSummary();
  }

  /**
   * Get migration history
   */
  getMigrationHistory() {
    return this.metrics.getMigrationHistory();
  }

  /**
   * Clear migration history
   */
  clearMigrationHistory(): void {
    this.metrics.clearHistory();
  }

  /**
   * Print formatted migration summary
   */
  private printMigrationSummary(
    results: MigrationContext[],
    allSuccessful: boolean,
  ): void {
    const summary = this.metrics.getMetricsSummary();

    this.logger.log('\n📊 MIGRATION SUMMARY');
    this.logger.log('─────────────────────────────────────────');
    this.logger.log(`Total Migrations: ${summary.totalMigrations}`);
    this.logger.log(`✅ Successful: ${summary.successful}`);
    this.logger.log(`❌ Failed: ${summary.failed}`);
    this.logger.log(`⏮️  Rolled Back: ${summary.rolledBack}`);
    this.logger.log(
      `⏱️  Average Duration: ${Math.round(summary.averageDuration)}ms`,
    );
    this.logger.log('─────────────────────────────────────────');

    // Detailed results
    for (const result of results) {
      const statusIcon =
        result.status === 'completed'
          ? '✅'
          : result.status === 'failed'
            ? '❌'
            : '⏮️ ';
      this.logger.log(
        `${statusIcon} ${result.migrationName} [${result.duration}ms]`,
      );

      if (result.errors && result.errors.length > 0) {
        result.errors.forEach((err) =>
          this.logger.error(`   └─ ${err}`),
        );
      }
    }

    this.logger.log(
      `\n${allSuccessful ? '✅ All migrations completed successfully!' : '❌ Migration batch failed'}`,
    );
  }
}
