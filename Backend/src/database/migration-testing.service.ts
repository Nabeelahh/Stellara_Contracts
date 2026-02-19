/**
 * Migration Testing Service
 * Provides comprehensive testing utilities for migrations
 */

import { Injectable, Logger } from '@nestjs/common';
import { QueryRunner } from 'typeorm';
import { EnhancedMigration, MigrationContext } from './migration-strategy';
import { MigrationExecutor } from './migration-executor';

/**
 * Test result for a migration
 */
export interface MigrationTestResult {
  migrationName: string;
  testType: 'dry-run' | 'validation' | 'rollback' | 'integrity';
  passed: boolean;
  message: string;
  duration: number;
  errors?: string[];
}

/**
 * Migration testing service for pre-deployment verification
 */
@Injectable()
export class MigrationTestingService {
  private readonly logger = new Logger('MigrationTestingService');
  private readonly executor = new MigrationExecutor();

  /**
   * Run dry-run test to validate migration syntax and schema
   */
  async testMigrationDryRun(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<MigrationTestResult> {
    const startTime = Date.now();
    const result: MigrationTestResult = {
      migrationName: migration.name,
      testType: 'dry-run',
      passed: false,
      message: '',
      duration: 0,
    };

    try {
      this.logger.log(`[DRY-RUN] Testing ${migration.name}...`);

      // Execute in transaction that will be rolled back
      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      const context: MigrationContext = {
        migrationName: migration.name,
        timestamp: new Date(),
        executedQueries: [],
        status: 'in-progress',
      };

      await migration.up(queryRunner, context);

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }

      result.passed = true;
      result.message = `Migration syntax and schema validation successful (${context.executedQueries.length} queries executed)`;
      result.duration = Date.now() - startTime;

      this.logger.log(`[DRY-RUN] ✅ ${result.message}`);
    } catch (error) {
      result.passed = false;
      result.message = 'Migration dry-run failed';
      result.errors = [
        error instanceof Error ? error.message : String(error),
      ];
      result.duration = Date.now() - startTime;

      this.logger.error(`[DRY-RUN] ❌ ${result.message}: ${result.errors[0]}`);

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }
    }

    return result;
  }

  /**
   * Test migration validation rules
   */
  async testMigrationValidation(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<MigrationTestResult> {
    const startTime = Date.now();
    const result: MigrationTestResult = {
      migrationName: migration.name,
      testType: 'validation',
      passed: false,
      message: '',
      duration: 0,
      errors: [],
    };

    try {
      this.logger.log(`[VALIDATION] Testing ${migration.name}...`);

      const preValidationFailed = !migration.preValidationRules;
      const postValidationFailed = !migration.postValidationRules;

      if (preValidationFailed && postValidationFailed) {
        result.passed = true;
        result.message = 'No validation rules defined';
        result.duration = Date.now() - startTime;
        this.logger.log(`[VALIDATION] ⚠️  ${result.message}`);
        return result;
      }

      if (migration.preValidationRules && migration.preValidationRules.length > 0) {
        for (const rule of migration.preValidationRules) {
          try {
            const isValid = await rule.validate(queryRunner);
            if (!isValid) {
              result.errors?.push(`[Pre] ${rule.errorMessage}`);
            }
          } catch (error) {
            result.errors?.push(
              `[Pre] ${rule.name}: ${error instanceof Error ? error.message : String(error)}`,
            );
          }
        }
      }

      if (migration.postValidationRules && migration.postValidationRules.length > 0) {
        for (const rule of migration.postValidationRules) {
          try {
            const isValid = await rule.validate(queryRunner);
            if (!isValid) {
              result.errors?.push(`[Post] ${rule.errorMessage}`);
            }
          } catch (error) {
            result.errors?.push(
              `[Post] ${rule.name}: ${error instanceof Error ? error.message : String(error)}`,
            );
          }
        }
      }

      result.passed = result.errors!.length === 0;
      result.message = result.passed
        ? 'All validation rules passed'
        : `${result.errors!.length} validation rule(s) failed`;
      result.duration = Date.now() - startTime;

      this.logger.log(`[VALIDATION] ${result.passed ? '✅' : '❌'} ${result.message}`);
    } catch (error) {
      result.passed = false;
      result.message = 'Validation test failed';
      result.errors = [
        error instanceof Error ? error.message : String(error),
      ];
      result.duration = Date.now() - startTime;

      this.logger.error(`[VALIDATION] ❌ ${result.message}`);
    }

    return result;
  }

  /**
   * Test rollback capability
   */
  async testMigrationRollback(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<MigrationTestResult> {
    const startTime = Date.now();
    const result: MigrationTestResult = {
      migrationName: migration.name,
      testType: 'rollback',
      passed: false,
      message: '',
      duration: 0,
    };

    if (!migration.rollback && !migration.down) {
      result.passed = true;
      result.message = 'Migration has no rollback implementation (down method will be used)';
      result.duration = Date.now() - startTime;
      this.logger.log(`[ROLLBACK] ⚠️  ${result.message}`);
      return result;
    }

    try {
      this.logger.log(`[ROLLBACK] Testing rollback for ${migration.name}...`);

      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      const context: MigrationContext = {
        migrationName: migration.name,
        timestamp: new Date(),
        executedQueries: [],
        status: 'in-progress',
      };

      // Execute up
      await migration.up(queryRunner, context);

      // Execute rollback
      if (migration.rollback) {
        await migration.rollback(queryRunner, context);
      } else {
        await migration.down(queryRunner, context);
      }

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }

      result.passed = true;
      result.message = 'Rollback executed successfully';
      result.duration = Date.now() - startTime;

      this.logger.log(`[ROLLBACK] ✅ ${result.message}`);
    } catch (error) {
      result.passed = false;
      result.message = 'Rollback test failed';
      result.errors = [
        error instanceof Error ? error.message : String(error),
      ];
      result.duration = Date.now() - startTime;

      this.logger.error(`[ROLLBACK] ❌ ${result.message}: ${result.errors[0]}`);

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }
    }

    return result;
  }

  /**
   * Test data integrity before and after migration
   */
  async testDataIntegrity(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<MigrationTestResult> {
    const startTime = Date.now();
    const result: MigrationTestResult = {
      migrationName: migration.name,
      testType: 'integrity',
      passed: false,
      message: '',
      duration: 0,
      errors: [],
    };

    if (!migration.backupStrategy || migration.backupStrategy.tables.length === 0) {
      result.passed = true;
      result.message = 'No backup tables defined for integrity check';
      result.duration = Date.now() - startTime;
      this.logger.log(`[INTEGRITY] ⚠️  ${result.message}`);
      return result;
    }

    try {
      this.logger.log(`[INTEGRITY] Testing data integrity for ${migration.name}...`);

      const tableCounts: Record<string, number> = {};

      // Get row counts before migration
      for (const tableName of migration.backupStrategy.tables) {
        try {
          const result = await queryRunner.query(
            `SELECT COUNT(*) as count FROM "${tableName}"`,
          );
          tableCounts[`${tableName}_before`] = Number(result[0].count);
        } catch {
          // Table might not exist yet
          tableCounts[`${tableName}_before`] = 0;
        }
      }

      if (!queryRunner.isTransactionActive) {
        await queryRunner.startTransaction();
      }

      const context: MigrationContext = {
        migrationName: migration.name,
        timestamp: new Date(),
        executedQueries: [],
        status: 'in-progress',
      };

      await migration.up(queryRunner, context);

      // Get row counts after migration
      for (const tableName of migration.backupStrategy.tables) {
        try {
          const result = await queryRunner.query(
            `SELECT COUNT(*) as count FROM "${tableName}"`,
          );
          tableCounts[`${tableName}_after`] = Number(result[0].count);
        } catch {
          tableCounts[`${tableName}_after`] = 0;
        }
      }

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }

      // Verify no data was lost
      let dataLossDetected = false;
      for (const tableName of migration.backupStrategy.tables) {
        const before = tableCounts[`${tableName}_before`] || 0;
        const after = tableCounts[`${tableName}_after`] || 0;

        if (after < before) {
          result.errors?.push(
            `Data loss in ${tableName}: ${before} → ${after} rows`,
          );
          dataLossDetected = true;
        }

        this.logger.log(
          `  ${tableName}: ${before} → ${after} rows`,
        );
      }

      result.passed = !dataLossDetected;
      result.message = dataLossDetected
        ? 'Data loss detected'
        : 'All data preserved during migration';
      result.duration = Date.now() - startTime;

      this.logger.log(`[INTEGRITY] ${result.passed ? '✅' : '❌'} ${result.message}`);
    } catch (error) {
      result.passed = false;
      result.message = 'Data integrity test failed';
      result.errors = [
        error instanceof Error ? error.message : String(error),
      ];
      result.duration = Date.now() - startTime;

      this.logger.error(`[INTEGRITY] ❌ ${result.message}`);

      if (queryRunner.isTransactionActive) {
        await queryRunner.rollbackTransaction();
      }
    }

    return result;
  }

  /**
   * Run comprehensive migration test suite
   */
  async runComprehensiveTest(
    queryRunner: QueryRunner,
    migration: EnhancedMigration,
  ): Promise<MigrationTestResult[]> {
    this.logger.log(
      `\n🧪 Running comprehensive test suite for ${migration.name}`,
    );
    this.logger.log('════════════════════════════════════════════════');

    const results: MigrationTestResult[] = [];

    // Run all tests
    const tests = [
      () => this.testMigrationValidation(queryRunner, migration),
      () => this.testMigrationDryRun(queryRunner, migration),
      () => this.testDataIntegrity(queryRunner, migration),
      () => this.testMigrationRollback(queryRunner, migration),
    ];

    for (const test of tests) {
      const result = await test();
      results.push(result);
    }

    // Print summary
    const passed = results.filter((r) => r.passed).length;
    const total = results.length;

    this.logger.log('════════════════════════════════════════════════');
    this.logger.log(`📊 Test Results: ${passed}/${total} passed`);

    for (const result of results) {
      const icon = result.passed ? '✅' : '❌';
      this.logger.log(
        `${icon} ${result.testType.toUpperCase()} - ${result.message} (${result.duration}ms)`,
      );
      if (result.errors && result.errors.length > 0) {
        result.errors.forEach((err) =>
          this.logger.error(`   └─ ${err}`),
        );
      }
    }

    this.logger.log('════════════════════════════════════════════════\n');

    return results;
  }
}
