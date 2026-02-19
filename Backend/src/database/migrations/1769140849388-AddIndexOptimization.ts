/**
 * Example Migration: AddIndexOptimization
 * 
 * This migration adds performance indexes to critical columns.
 * It demonstrates:
 * - Data integrity checks
 * - Safe index creation
 * - Rollback procedures
 */

import { QueryRunner } from 'typeorm';
import {
  EnhancedMigration,
  MigrationContext,
  MigrationValidator,
  BackupStrategy,
} from '../migration-strategy';

export class AddIndexOptimization1769140849388 implements EnhancedMigration {
  name = 'AddIndexOptimization1769140849388';
  version = '1.0.0';
  description = 'Add performance optimization indexes to critical columns';

  backupStrategy: BackupStrategy = {
    tables: ['workflows', 'workflow_steps', 'stellar_events'],
    strategy: 'snapshot',
  };

  preValidationRules = [
    MigrationValidator.commonRules.tableExists('workflows'),
    MigrationValidator.commonRules.columnExists('workflows', 'state'),
    MigrationValidator.commonRules.columnExists('workflows', 'createdAt'),
    MigrationValidator.commonRules.tableExists('stellar_events'),
    MigrationValidator.commonRules.columnExists('stellar_events', 'ledgerSequence'),
  ];

  postValidationRules = [
    MigrationValidator.commonRules.indexExists('idx_workflows_state_created'),
    MigrationValidator.commonRules.indexExists('idx_workflows_type_state'),
    MigrationValidator.commonRules.indexExists('idx_stellar_events_ledger_ts'),
  ];

  async up(queryRunner: QueryRunner, context: MigrationContext): Promise<void> {
    // Add composite indexes for queries
    const indexes = [
      {
        name: 'idx_workflows_state_created',
        query: `
          CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_state_created
          ON workflows(state, "createdAt" DESC)
          WHERE state IN ('pending', 'running')
        `,
      },
      {
        name: 'idx_workflows_type_state',
        query: `
          CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_type_state
          ON workflows(type, state)
          WHERE state != 'completed'
        `,
      },
      {
        name: 'idx_stellar_events_ledger_ts',
        query: `
          CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_stellar_events_ledger_ts
          ON stellar_events(ledgerSequence DESC, "timestamp" DESC)
        `,
      },
      {
        name: 'idx_stellar_events_delivery',
        query: `
          CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_stellar_events_delivery
          ON stellar_events("deliveryStatus", "lastAttemptAt")
          WHERE "deliveryStatus" = 'pending'
        `,
      },
    ];

    for (const index of indexes) {
      try {
        await queryRunner.query(index.query);
        context.executedQueries.push(index.name);
      } catch (error) {
        if (error instanceof Error && error.message.includes('already exists')) {
          // Index already exists, continue
          context.executedQueries.push(`${index.name} (already exists)`);
        } else {
          throw error;
        }
      }
    }

    // Analyze updated tables for query planner
    const tablesToAnalyze = ['workflows', 'stellar_events', 'workflow_steps'];
    for (const tableName of tablesToAnalyze) {
      await queryRunner.query(`ANALYZE ${tableName}`);
      context.executedQueries.push(`ANALYZE ${tableName}`);
    }
  }

  async down(queryRunner: QueryRunner, context: MigrationContext): Promise<void> {
    const indexesToDrop = [
      'idx_workflows_state_created',
      'idx_workflows_type_state',
      'idx_stellar_events_ledger_ts',
      'idx_stellar_events_delivery',
    ];

    for (const indexName of indexesToDrop) {
      try {
        await queryRunner.query(`DROP INDEX IF EXISTS ${indexName}`);
        context.executedQueries.push(`DROP INDEX ${indexName}`);
      } catch (error) {
        // Index might not exist, continue
      }
    }
  }

  async rollback(
    queryRunner: QueryRunner,
    context: MigrationContext,
  ): Promise<void> {
    await this.down(queryRunner, context);
  }
}
