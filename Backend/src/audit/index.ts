// Main exports
export { AuditModule } from './audit.module';
export { AuditService } from './audit.service';
export { AuditRetentionService } from './audit-retention.service';
export { AuditController } from './audit.controller';

// Interceptors
export { AuditInterceptor } from './interceptors/audit.interceptor';

// Middleware
export { AuditContextMiddleware } from './middleware/audit-context.middleware';

// Decorators
export {
  Audit,
  SkipAudit,
  AuditCreate,
  AuditRead,
  AuditUpdate,
  AuditDelete,
} from './decorators/audit.decorator';

// Interfaces
export {
  AuditLogEntry,
  AuditContext,
  DataChangeRecord,
  AuditQueryOptions,
  AuditQueryResult,
  RetentionPolicyConfig,
  RetentionExecutionResult,
  AuditMetadata,
  AUDIT_METADATA_KEY,
  SKIP_AUDIT_KEY,
} from './interfaces/audit.interface';

// DTOs
export {
  QueryAuditLogsDto,
  GetEntityHistoryDto,
  GetStatisticsDto,
  CreateRetentionPolicyDto,
  UpdateRetentionPolicyDto,
} from './dto/audit.dto';
