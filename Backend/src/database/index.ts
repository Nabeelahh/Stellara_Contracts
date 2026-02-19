/**
 * Database Module Exports
 * Central export point for all migration and database utilities
 */

// Migration Strategy & Core
export {
  MigrationContext,
  MigrationValidationRule,
  BackupStrategy,
  EnhancedMigration,
  MigrationValidator,
  MigrationBackup,
  MigrationRollback,
  MigrationMetrics,
} from './migration-strategy';

// Migration Executor
export { MigrationExecutor } from './migration-executor';

// Migration Testing
export {
  MigrationTestResult,
  MigrationTestingService,
} from './migration-testing.service';

// Migration Manager
export { MigrationManagerService } from './migration-manager.service';

// Migration Utilities
export {
  MigrationTableUtils,
  MigrationIndexUtils,
  MigrationConstraintUtils,
  MigrationDataUtils,
  MigrationTypeUtils,
  MigrationDatabaseUtils,
} from './migration-utils';

// Database Module
export { DatabaseModule } from './database.module';
