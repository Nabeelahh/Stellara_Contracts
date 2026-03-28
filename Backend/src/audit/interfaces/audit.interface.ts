import { AuditAction } from '@prisma/client';

export interface AuditLogEntry {
  correlationId?: string;
  tenantId?: string;
  userId?: string;
  action: AuditAction;
  entityType: string;
  entityId?: string;
  method?: string;
  path?: string;
  statusCode?: number;
  ipAddress?: string;
  userAgent?: string;
  requestBody?: Record<string, unknown>;
  responseBody?: Record<string, unknown>;
  previousState?: Record<string, unknown>;
  newState?: Record<string, unknown>;
  changedFields?: string[];
  metadata?: Record<string, unknown>;
  duration?: number;
  errorMessage?: string;
}

export interface AuditContext {
  correlationId?: string;
  tenantId?: string;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface DataChangeRecord {
  entityType: string;
  entityId: string;
  previousState?: Record<string, unknown>;
  newState?: Record<string, unknown>;
  changedFields: string[];
}

export interface AuditQueryOptions {
  tenantId?: string;
  userId?: string;
  entityType?: string;
  entityId?: string;
  action?: AuditAction;
  correlationId?: string;
  startDate?: Date;
  endDate?: Date;
  statusCode?: number;
  page?: number;
  limit?: number;
  sortBy?: 'createdAt' | 'action' | 'entityType';
  sortOrder?: 'asc' | 'desc';
}

export interface AuditQueryResult {
  data: AuditLogEntry[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface RetentionPolicyConfig {
  name: string;
  tenantId?: string;
  retentionDays: number;
  entityTypes?: string[];
  actions?: AuditAction[];
  archiveEnabled?: boolean;
  archiveLocation?: string;
}

export interface RetentionExecutionResult {
  policyId: string;
  policyName: string;
  deletedCount: number;
  archivedCount: number;
  executedAt: Date;
  errors?: string[];
}

export const AUDIT_METADATA_KEY = 'audit:metadata';
export const SKIP_AUDIT_KEY = 'audit:skip';

export interface AuditMetadata {
  entityType: string;
  action?: AuditAction;
  captureRequestBody?: boolean;
  captureResponseBody?: boolean;
  sensitiveFields?: string[];
}
