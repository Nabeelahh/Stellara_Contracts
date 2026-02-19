/**
 * Example Migration: AddAuditLogging
 * 
 * This migration adds an audit_logs table with comprehensive logging capabilities.
 * It demonstrates proper use of the migration strategy with:
 * - Pre-migration validation
 * - Data backup
 * - Post-migration validation
 * - Rollback support
 */

import { QueryRunner } from 'typeorm';
import {
  EnhancedMigration,
  MigrationContext,
  MigrationValidator,
  BackupStrategy,
} from '../migration-strategy';

export class AddAuditLogging1769140849387 implements EnhancedMigration {
  name = 'AddAuditLogging1769140849387';
  version = '1.0.0';
  description = 'Add comprehensive audit logging table for tracking all database changes';

  backupStrategy: BackupStrategy = {
    tables: ['workflows', 'workflow_steps', 'stellar_events'],
    strategy: 'full',
  };

  preValidationRules = [
    MigrationValidator.commonRules.tableExists('workflows'),
    MigrationValidator.commonRules.tableExists('workflow_steps'),
  ];

  postValidationRules = [
    MigrationValidator.commonRules.tableExists('audit_logs'),
    MigrationValidator.commonRules.columnExists('audit_logs', 'id'),
    MigrationValidator.commonRules.columnExists('audit_logs', 'entity_type'),
    MigrationValidator.commonRules.columnExists('audit_logs', 'operation'),
  ];

  async up(queryRunner: QueryRunner, context: MigrationContext): Promise<void> {
    // Create audit_logs table
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "audit_logs" (
        "id" uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
        "entity_type" VARCHAR(100) NOT NULL,
        "entity_id" VARCHAR(255) NOT NULL,
        "operation" VARCHAR(50) NOT NULL CHECK ("operation" IN ('CREATE', 'UPDATE', 'DELETE')),
        "old_values" JSONB,
        "new_values" JSONB NOT NULL,
        "changed_by" VARCHAR(255),
        "change_reason" TEXT,
        "ip_address" VARCHAR(45),
        "user_agent" TEXT,
        "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        "metadata" JSONB
      )
    `);

    context.executedQueries.push('CREATE TABLE audit_logs');

    // Create indexes for performance
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_operation ON audit_logs(operation)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_audit_logs_changed_by ON audit_logs(changed_by)',
    ];

    for (const indexQuery of indexes) {
      await queryRunner.query(indexQuery);
      context.executedQueries.push(indexQuery);
    }

    // Create trigger function for audit logging
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION audit_log_trigger()
      RETURNS TRIGGER AS $$
      BEGIN
        INSERT INTO audit_logs (
          entity_type,
          entity_id,
          operation,
          old_values,
          new_values,
          created_at
        ) VALUES (
          TG_TABLE_NAME,
          NEW.id::text,
          TG_OP,
          CASE WHEN TG_OP = 'UPDATE' THEN row_to_json(OLD) ELSE NULL END,
          row_to_json(NEW),
          NOW()
        );
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    context.executedQueries.push('CREATE FUNCTION audit_log_trigger');

    // Create triggers for key tables
    const triggerTables = ['workflows', 'workflow_steps', 'stellar_events'];
    for (const tableName of triggerTables) {
      await queryRunner.query(`
        CREATE TRIGGER ${tableName}_audit_trigger
        AFTER INSERT OR UPDATE OR DELETE ON ${tableName}
        FOR EACH ROW
        EXECUTE FUNCTION audit_log_trigger();
      `);

      context.executedQueries.push(
        `CREATE TRIGGER ${tableName}_audit_trigger`,
      );
    }
  }

  async down(queryRunner: QueryRunner, context: MigrationContext): Promise<void> {
    // Drop triggers
    const triggerTables = ['workflows', 'workflow_steps', 'stellar_events'];
    for (const tableName of triggerTables) {
      await queryRunner.query(
        `DROP TRIGGER IF EXISTS ${tableName}_audit_trigger ON ${tableName}`,
      );
      context.executedQueries.push(
        `DROP TRIGGER ${tableName}_audit_trigger`,
      );
    }

    // Drop trigger function
    await queryRunner.query('DROP FUNCTION IF EXISTS audit_log_trigger()');
    context.executedQueries.push('DROP FUNCTION audit_log_trigger');

    // Drop indexes
    const indexes = [
      'idx_audit_logs_entity',
      'idx_audit_logs_operation',
      'idx_audit_logs_created_at',
      'idx_audit_logs_changed_by',
    ];

    for (const indexName of indexes) {
      await queryRunner.query(`DROP INDEX IF EXISTS ${indexName}`);
      context.executedQueries.push(`DROP INDEX ${indexName}`);
    }

    // Drop table
    await queryRunner.query('DROP TABLE IF EXISTS audit_logs');
    context.executedQueries.push('DROP TABLE audit_logs');
  }

  async rollback(
    queryRunner: QueryRunner,
    context: MigrationContext,
  ): Promise<void> {
    // Same as down
    await this.down(queryRunner, context);
  }
}
