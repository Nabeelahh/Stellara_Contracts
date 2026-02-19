/**
 * Migration Utilities
 * Common helper functions for migration operations
 */

import { QueryRunner } from 'typeorm';

/**
 * Common table operations for migrations
 */
export class MigrationTableUtils {
  /**
   * Create table with comprehensive configuration
   */
  static async createTable(
    queryRunner: QueryRunner,
    tableName: string,
    columns: string,
    options?: {
      ifNotExists?: boolean;
      comment?: string;
    },
  ): Promise<void> {
    const ifNotExists = options?.ifNotExists ? 'IF NOT EXISTS' : '';
    const query = `CREATE TABLE ${ifNotExists} "${tableName}" (${columns})`;
    await queryRunner.query(query);
  }

  /**
   * Drop table safely
   */
  static async dropTable(
    queryRunner: QueryRunner,
    tableName: string,
    options?: {
      ifExists?: boolean;
      cascade?: boolean;
    },
  ): Promise<void> {
    const ifExists = options?.ifExists ? 'IF EXISTS' : '';
    const cascade = options?.cascade ? 'CASCADE' : '';
    const query = `DROP TABLE ${ifExists} "${tableName}" ${cascade}`;
    await queryRunner.query(query);
  }

  /**
   * Add column to table
   */
  static async addColumn(
    queryRunner: QueryRunner,
    tableName: string,
    columnDef: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" ADD COLUMN ${columnDef}`;
    await queryRunner.query(query);
  }

  /**
   * Drop column from table
   */
  static async dropColumn(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
    options?: { ifExists?: boolean },
  ): Promise<void> {
    const ifExists = options?.ifExists ? 'IF EXISTS' : '';
    const query = `ALTER TABLE "${tableName}" DROP COLUMN ${ifExists} "${columnName}"`;
    await queryRunner.query(query);
  }

  /**
   * Modify column type
   */
  static async alterColumn(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
    newType: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" ALTER COLUMN "${columnName}" TYPE ${newType}`;
    await queryRunner.query(query);
  }

  /**
   * Rename column
   */
  static async renameColumn(
    queryRunner: QueryRunner,
    tableName: string,
    oldColumnName: string,
    newColumnName: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" RENAME COLUMN "${oldColumnName}" TO "${newColumnName}"`;
    await queryRunner.query(query);
  }

  /**
   * Check if column exists
   */
  static async columnExists(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
  ): Promise<boolean> {
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
  }

  /**
   * Get column information
   */
  static async getColumnInfo(
    queryRunner: QueryRunner,
    tableName: string,
    columnName: string,
  ): Promise<any> {
    const result = await queryRunner.query(
      `SELECT column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_name = $1 AND column_name = $2`,
      [tableName, columnName],
    );
    return result[0] || null;
  }
}

/**
 * Index operations for migrations
 */
export class MigrationIndexUtils {
  /**
   * Create index
   */
  static async createIndex(
    queryRunner: QueryRunner,
    indexName: string,
    tableName: string,
    columns: string | string[],
    options?: {
      unique?: boolean;
      concurrent?: boolean;
      where?: string;
    },
  ): Promise<void> {
    const unique = options?.unique ? 'UNIQUE' : '';
    const concurrent = options?.concurrent ? 'CONCURRENTLY' : '';
    const columnList =
      typeof columns === 'string'
        ? columns
        : `(${columns.join(', ')})`;
    const where = options?.where ? `WHERE ${options.where}` : '';

    const query = `CREATE ${unique} INDEX ${concurrent} IF NOT EXISTS ${indexName} ON "${tableName}" ${columnList} ${where}`;
    await queryRunner.query(query);
  }

  /**
   * Drop index
   */
  static async dropIndex(
    queryRunner: QueryRunner,
    indexName: string,
    options?: { ifExists?: boolean; concurrent?: boolean },
  ): Promise<void> {
    const ifExists = options?.ifExists ? 'IF EXISTS' : '';
    const concurrent = options?.concurrent ? 'CONCURRENTLY' : '';
    const query = `DROP INDEX ${ifExists} ${concurrent} ${indexName}`;
    await queryRunner.query(query);
  }

  /**
   * Check if index exists
   */
  static async indexExists(
    queryRunner: QueryRunner,
    indexName: string,
  ): Promise<boolean> {
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
  }

  /**
   * Get index information
   */
  static async getIndexInfo(
    queryRunner: QueryRunner,
    indexName: string,
  ): Promise<any> {
    const result = await queryRunner.query(
      `SELECT indexname, tablename, indexdef
       FROM pg_indexes
       WHERE indexname = $1`,
      [indexName],
    );
    return result[0] || null;
  }
}

/**
 * Constraint operations for migrations
 */
export class MigrationConstraintUtils {
  /**
   * Add foreign key constraint
   */
  static async addForeignKey(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
    columnName: string,
    referencedTableName: string,
    referencedColumnName: string,
    options?: {
      onDelete?: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
      onUpdate?: 'CASCADE' | 'SET NULL' | 'RESTRICT' | 'NO ACTION';
    },
  ): Promise<void> {
    const onDelete = options?.onDelete || 'RESTRICT';
    const onUpdate = options?.onUpdate || 'RESTRICT';

    const query = `
      ALTER TABLE "${tableName}"
      ADD CONSTRAINT "${constraintName}"
      FOREIGN KEY ("${columnName}")
      REFERENCES "${referencedTableName}"("${referencedColumnName}")
      ON DELETE ${onDelete}
      ON UPDATE ${onUpdate}
    `;
    await queryRunner.query(query);
  }

  /**
   * Drop foreign key constraint
   */
  static async dropForeignKey(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" DROP CONSTRAINT IF EXISTS "${constraintName}"`;
    await queryRunner.query(query);
  }

  /**
   * Add unique constraint
   */
  static async addUniqueConstraint(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
    columns: string | string[],
  ): Promise<void> {
    const columnList =
      typeof columns === 'string' ? columns : columns.join(', ');
    const query = `
      ALTER TABLE "${tableName}"
      ADD CONSTRAINT "${constraintName}"
      UNIQUE (${columnList})
    `;
    await queryRunner.query(query);
  }

  /**
   * Drop unique constraint
   */
  static async dropUniqueConstraint(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" DROP CONSTRAINT IF EXISTS "${constraintName}"`;
    await queryRunner.query(query);
  }

  /**
   * Add check constraint
   */
  static async addCheckConstraint(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
    condition: string,
  ): Promise<void> {
    const query = `
      ALTER TABLE "${tableName}"
      ADD CONSTRAINT "${constraintName}"
      CHECK (${condition})
    `;
    await queryRunner.query(query);
  }

  /**
   * Drop check constraint
   */
  static async dropCheckConstraint(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
  ): Promise<void> {
    const query = `ALTER TABLE "${tableName}" DROP CONSTRAINT IF EXISTS "${constraintName}"`;
    await queryRunner.query(query);
  }

  /**
   * Check if constraint exists
   */
  static async constraintExists(
    queryRunner: QueryRunner,
    tableName: string,
    constraintName: string,
  ): Promise<boolean> {
    try {
      const result = await queryRunner.query(
        `SELECT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE table_name = $1 AND constraint_name = $2
        )`,
        [tableName, constraintName],
      );
      return result[0].exists;
    } catch {
      return false;
    }
  }
}

/**
 * Data operations for migrations
 */
export class MigrationDataUtils {
  /**
   * Backup table data
   */
  static async backupTable(
    queryRunner: QueryRunner,
    tableName: string,
    backupTableName: string,
  ): Promise<number> {
    await queryRunner.query(
      `CREATE TABLE IF NOT EXISTS "${backupTableName}" AS SELECT * FROM "${tableName}"`,
    );

    const result = await queryRunner.query(
      `SELECT COUNT(*) as count FROM "${tableName}"`,
    );
    return Number(result[0].count);
  }

  /**
   * Restore table data from backup
   */
  static async restoreTable(
    queryRunner: QueryRunner,
    backupTableName: string,
    tableName: string,
  ): Promise<number> {
    await queryRunner.query(`TRUNCATE TABLE "${tableName}" CASCADE`);

    const result = await queryRunner.query(
      `SELECT COUNT(*) as count FROM "${backupTableName}"`,
    );

    await queryRunner.query(
      `INSERT INTO "${tableName}" SELECT * FROM "${backupTableName}"`,
    );

    return Number(result[0].count);
  }

  /**
   * Delete backup table
   */
  static async deleteBackup(
    queryRunner: QueryRunner,
    backupTableName: string,
  ): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "${backupTableName}"`);
  }

  /**
   * Get row count for table
   */
  static async getRowCount(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<number> {
    const result = await queryRunner.query(
      `SELECT COUNT(*) as count FROM "${tableName}"`,
    );
    return Number(result[0].count);
  }

  /**
   * Execute batch update
   */
  static async batchUpdate(
    queryRunner: QueryRunner,
    tableName: string,
    updateQuery: string,
    batchSize: number = 1000,
  ): Promise<number> {
    const totalCount = await this.getRowCount(queryRunner, tableName);
    let processedCount = 0;

    for (let offset = 0; offset < totalCount; offset += batchSize) {
      await queryRunner.query(
        `${updateQuery} OFFSET ${offset} LIMIT ${batchSize}`,
      );
      processedCount += batchSize;
    }

    return processedCount;
  }

  /**
   * Copy data with transformation
   */
  static async copyDataWithTransform(
    queryRunner: QueryRunner,
    sourceTable: string,
    targetTable: string,
    mapping: Record<string, string>, // { sourceCol: 'targetCol AS transformation' }
  ): Promise<number> {
    const mappingStr = Object.entries(mapping)
      .map(([source, target]) => `${source} AS ${target}`)
      .join(', ');

    const result = await queryRunner.query(
      `INSERT INTO "${targetTable}" SELECT ${mappingStr} FROM "${sourceTable}"`,
    );

    return result.affectedRows || 0;
  }

  /**
   * Validate data consistency
   */
  static async validateDataConsistency(
    queryRunner: QueryRunner,
    tableName: string,
    validationQuery: string,
  ): Promise<boolean> {
    const result = await queryRunner.query(validationQuery);
    return result.length === 0; // No inconsistencies found
  }
}

/**
 * Type and enum operations
 */
export class MigrationTypeUtils {
  /**
   * Create custom type (enum)
   */
  static async createType(
    queryRunner: QueryRunner,
    typeName: string,
    values: string[],
  ): Promise<void> {
    const valueList = values.map((v) => `'${v}'`).join(', ');
    const query = `CREATE TYPE "${typeName}" AS ENUM (${valueList})`;
    await queryRunner.query(query);
  }

  /**
   * Drop custom type
   */
  static async dropType(
    queryRunner: QueryRunner,
    typeName: string,
    options?: { ifExists?: boolean; cascade?: boolean },
  ): Promise<void> {
    const ifExists = options?.ifExists ? 'IF EXISTS' : '';
    const cascade = options?.cascade ? 'CASCADE' : '';
    const query = `DROP TYPE ${ifExists} "${typeName}" ${cascade}`;
    await queryRunner.query(query);
  }

  /**
   * Add value to enum
   */
  static async addEnumValue(
    queryRunner: QueryRunner,
    typeName: string,
    newValue: string,
    options?: { before?: string; after?: string },
  ): Promise<void> {
    let query = `ALTER TYPE "${typeName}" ADD VALUE '${newValue}'`;
    if (options?.before) {
      query += ` BEFORE '${options.before}'`;
    } else if (options?.after) {
      query += ` AFTER '${options.after}'`;
    }
    await queryRunner.query(query);
  }
}

/**
 * Database utility operations
 */
export class MigrationDatabaseUtils {
  /**
   * Analyze table for query planner optimization
   */
  static async analyzeTable(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<void> {
    await queryRunner.query(`ANALYZE "${tableName}"`);
  }

  /**
   * Vacuum table to reclaim space
   */
  static async vacuumTable(
    queryRunner: QueryRunner,
    tableName: string,
    analyze?: boolean,
  ): Promise<void> {
    const cmd = analyze ? 'VACUUM ANALYZE' : 'VACUUM';
    await queryRunner.query(`${cmd} "${tableName}"`);
  }

  /**
   * Reindex table
   */
  static async reindexTable(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<void> {
    await queryRunner.query(`REINDEX TABLE "${tableName}"`);
  }

  /**
   * Get table statistics
   */
  static async getTableStats(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<any> {
    const result = await queryRunner.query(
      `SELECT 
        schemaname,
        tablename,
        n_live_tup as live_rows,
        n_dead_tup as dead_rows,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze
       FROM pg_stat_user_tables
       WHERE tablename = $1`,
      [tableName],
    );
    return result[0] || null;
  }

  /**
   * Disable/enable triggers temporarily
   */
  static async disableTriggers(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<void> {
    await queryRunner.query(`ALTER TABLE "${tableName}" DISABLE TRIGGER ALL`);
  }

  static async enableTriggers(
    queryRunner: QueryRunner,
    tableName: string,
  ): Promise<void> {
    await queryRunner.query(`ALTER TABLE "${tableName}" ENABLE TRIGGER ALL`);
  }
}
