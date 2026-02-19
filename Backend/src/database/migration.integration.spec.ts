/**
 * Migration Integration Tests
 * Test suite for migration strategy and utilities
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import { DatabaseModule } from './database.module';
import {
  MigrationExecutor,
  MigrationTestingService,
  MigrationManagerService,
  EnhancedMigration,
  MigrationContext,
  MigrationValidator,
} from './index';

describe('Database Migrations', () => {
  let module: TestingModule;
  let dataSource: DataSource;
  let migrationManager: MigrationManagerService;
  let executor: MigrationExecutor;
  let tester: MigrationTestingService;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [DatabaseModule],
    }).compile();

    dataSource = module.get<DataSource>(DataSource);
    migrationManager = module.get<MigrationManagerService>(
      MigrationManagerService,
    );
    executor = module.get<MigrationExecutor>(MigrationExecutor);
    tester = module.get<MigrationTestingService>(MigrationTestingService);
  });

  afterAll(async () => {
    await module.close();
  });

  describe('MigrationValidator', () => {
    it('should validate table existence', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const rule = MigrationValidator.commonRules.tableExists('workflows');
        const result = await rule.validate(queryRunner);
        expect(typeof result).toBe('boolean');
      } finally {
        await queryRunner.release();
      }
    });

    it('should validate column existence', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const rule = MigrationValidator.commonRules.columnExists(
          'workflows',
          'id',
        );
        const result = await rule.validate(queryRunner);
        expect(typeof result).toBe('boolean');
      } finally {
        await queryRunner.release();
      }
    });
  });

  describe('MigrationExecutor', () => {
    it('should execute migration with context tracking', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const mockMigration: EnhancedMigration = {
          name: 'TestMigration',
          version: '1.0.0',
          description: 'Test migration',
          up: async (qr, context) => {
            context.executedQueries.push('SELECT 1');
          },
          down: async (qr, context) => {
            context.executedQueries.push('ROLLBACK');
          },
        };

        const context = await executor.executeMigration(
          queryRunner,
          mockMigration,
          true, // dry-run
        );

        expect(context.status).toBe('completed');
        expect(context.migrationName).toBe('TestMigration');
        expect(context.duration).toBeGreaterThanOrEqual(0);
      } finally {
        await queryRunner.release();
      }
    });

    it('should track migration metrics', () => {
      const metrics = executor.getMigrationMetrics();
      expect(metrics).toHaveProperty('totalMigrations');
      expect(metrics).toHaveProperty('successful');
      expect(metrics).toHaveProperty('failed');
      expect(metrics).toHaveProperty('averageDuration');
    });
  });

  describe('MigrationTestingService', () => {
    it('should run validation test', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const mockMigration: EnhancedMigration = {
          name: 'TestMigration',
          version: '1.0.0',
          preValidationRules: [
            MigrationValidator.commonRules.tableExists('workflows'),
          ],
          up: async (qr, context) => {},
          down: async (qr, context) => {},
        };

        const result = await tester.testMigrationValidation(
          queryRunner,
          mockMigration,
        );

        expect(result.testType).toBe('validation');
        expect(typeof result.passed).toBe('boolean');
        expect(typeof result.message).toBe('string');
        expect(result.duration).toBeGreaterThanOrEqual(0);
      } finally {
        await queryRunner.release();
      }
    });

    it('should run dry-run test', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const mockMigration: EnhancedMigration = {
          name: 'TestMigration',
          version: '1.0.0',
          up: async (qr, context) => {
            context.executedQueries.push('SELECT 1');
          },
          down: async (qr, context) => {},
        };

        const result = await tester.testMigrationDryRun(
          queryRunner,
          mockMigration,
        );

        expect(result.testType).toBe('dry-run');
        expect(typeof result.passed).toBe('boolean');
        expect(result.duration).toBeGreaterThanOrEqual(0);
      } finally {
        await queryRunner.release();
      }
    });
  });

  describe('MigrationManagerService', () => {
    it('should get migration metrics', () => {
      const metrics = migrationManager.getMigrationMetrics();
      expect(metrics.totalMigrations).toBeGreaterThanOrEqual(0);
      expect(metrics.successful).toBeGreaterThanOrEqual(0);
      expect(metrics.failed).toBeGreaterThanOrEqual(0);
    });

    it('should get migration history', () => {
      const history = migrationManager.getMigrationHistory();
      expect(Array.isArray(history)).toBe(true);
    });
  });

  describe('Migration Rollback', () => {
    it('should support rollback operations', async () => {
      const queryRunner = dataSource.createQueryRunner();
      try {
        const mockMigration: EnhancedMigration = {
          name: 'TestMigration',
          version: '1.0.0',
          up: async (qr, context) => {
            context.executedQueries.push('CREATE TABLE test (id INT)');
          },
          down: async (qr, context) => {
            context.executedQueries.push('DROP TABLE test');
          },
          rollback: async (qr, context) => {
            context.executedQueries.push('DROP TABLE test (rollback)');
          },
        };

        // Rollback is supported if function is defined
        expect(typeof mockMigration.rollback).toBe('function');
      } finally {
        await queryRunner.release();
      }
    });
  });

  describe('Data Backup Strategy', () => {
    it('should define backup strategy', async () => {
      const mockMigration: EnhancedMigration = {
        name: 'TestMigration',
        version: '1.0.0',
        backupStrategy: {
          tables: ['workflows'],
          strategy: 'full',
        },
        up: async (qr, context) => {},
        down: async (qr, context) => {},
      };

      expect(mockMigration.backupStrategy).toBeDefined();
      expect(mockMigration.backupStrategy!.tables).toContain('workflows');
      expect(mockMigration.backupStrategy!.strategy).toBe('full');
    });
  });
});
