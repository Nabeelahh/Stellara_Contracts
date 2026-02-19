/**
 * Migration Manager Service
 * Provides CLI commands for managing migrations with the new strategy
 */

import { Injectable, Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { MigrationExecutor } from './migration-executor';
import { MigrationTestingService } from './migration-testing.service';
import { EnhancedMigration } from './migration-strategy';

/**
 * Service for managing migrations via CLI commands
 */
@Injectable()
export class MigrationManagerService {
  private readonly logger = new Logger('MigrationManager');
  private readonly executor = new MigrationExecutor();
  private readonly tester = new MigrationTestingService();

  constructor(private readonly dataSource: DataSource) {}

  /**
   * Test a migration before running it
   */
  async testMigration(migration: EnhancedMigration): Promise<boolean> {
    const queryRunner = this.dataSource.createQueryRunner();

    try {
      const results = await this.tester.runComprehensiveTest(
        queryRunner,
        migration,
      );

      const allPassed = results.every((r) => r.passed);

      if (!allPassed) {
        this.logger.error(
          `Migration ${migration.name} failed testing. Fix issues before running.`,
        );
      }

      return allPassed;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Run a single migration
   */
  async runMigration(
    migration: EnhancedMigration,
    options: { dryRun?: boolean; skipValidation?: boolean } = {},
  ): Promise<boolean> {
    const queryRunner = this.dataSource.createQueryRunner();

    try {
      if (!options.skipValidation) {
        this.logger.log(
          `Testing migration ${migration.name} before execution...`,
        );
        const testPassed = await this.testMigration(migration);

        if (!testPassed) {
          return false;
        }
      }

      this.logger.log(
        `Running migration ${migration.name}...`,
      );

      const context = await this.executor.executeMigration(
        queryRunner,
        migration,
        options.dryRun,
      );

      return context.status === 'completed';
    } catch (error) {
      this.logger.error(
        `Failed to run migration ${migration.name}: ${error instanceof Error ? error.message : String(error)}`,
      );
      return false;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Run multiple migrations in sequence
   */
  async runMigrations(
    migrations: EnhancedMigration[],
    options: { dryRun?: boolean; stopOnError?: boolean } = {},
  ): Promise<boolean> {
    const queryRunner = this.dataSource.createQueryRunner();

    try {
      this.logger.log(
        `Running migration batch (${migrations.length} migrations)...`,
      );

      const results = await this.executor.executeMigrations(
        queryRunner,
        migrations,
        options.dryRun,
      );

      const allSuccessful = results.every((r) => r.status === 'completed');

      if (!allSuccessful && options.stopOnError) {
        this.logger.error('Migration batch stopped due to error');
      }

      return allSuccessful;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Rollback the last migration
   */
  async rollbackMigration(migration: EnhancedMigration): Promise<boolean> {
    const queryRunner = this.dataSource.createQueryRunner();

    try {
      this.logger.log(`Rolling back migration ${migration.name}...`);
      await this.executor.rollbackLastMigration(queryRunner, migration);
      return true;
    } catch (error) {
      this.logger.error(
        `Rollback failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return false;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Get migration metrics
   */
  getMigrationMetrics() {
    return this.executor.getMigrationMetrics();
  }

  /**
   * Get migration history
   */
  getMigrationHistory() {
    return this.executor.getMigrationHistory();
  }

  /**
   * Print migration report
   */
  printMigrationReport(): void {
    const metrics = this.getMigrationMetrics();
    const history = this.getMigrationHistory();

    this.logger.log('\n📊 MIGRATION REPORT');
    this.logger.log('═════════════════════════════════════════');
    this.logger.log(`Total Migrations: ${metrics.totalMigrations}`);
    this.logger.log(`✅ Successful: ${metrics.successful}`);
    this.logger.log(`❌ Failed: ${metrics.failed}`);
    this.logger.log(`⏮️  Rolled Back: ${metrics.rolledBack}`);
    this.logger.log(
      `⏱️  Average Duration: ${Math.round(metrics.averageDuration)}ms`,
    );
    this.logger.log('═════════════════════════════════════════');

    if (history.length > 0) {
      this.logger.log('\n📋 Migration History:');
      for (const entry of history) {
        const icon =
          entry.status === 'completed'
            ? '✅'
            : entry.status === 'failed'
              ? '❌'
              : '⏮️ ';
        this.logger.log(
          `${icon} ${entry.migrationName} [${entry.duration}ms] - ${entry.status}`,
        );
      }
    }

    this.logger.log('═════════════════════════════════════════\n');
  }
}
