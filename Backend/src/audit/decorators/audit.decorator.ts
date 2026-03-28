import { AUDIT_METADATA_KEY, AuditMetadata, SKIP_AUDIT_KEY } from '../interfaces/audit.interface';

import { SetMetadata } from '@nestjs/common';

/**
 * Decorator to provide audit metadata for a controller method.
 *
 * @example
 * ```typescript
 * @Post()
 * @Audit({ entityType: 'User', captureRequestBody: true })
 * async createUser(@Body() dto: CreateUserDto) {
 *   return this.userService.create(dto);
 * }
 * ```
 */
export const Audit = (metadata: AuditMetadata) => SetMetadata(AUDIT_METADATA_KEY, metadata);

/**
 * Decorator to skip audit logging for a specific endpoint.
 *
 * @example
 * ```typescript
 * @Get('health')
 * @SkipAudit()
 * healthCheck() {
 *   return { status: 'ok' };
 * }
 * ```
 */
export const SkipAudit = () => SetMetadata(SKIP_AUDIT_KEY, true);

/**
 * Decorator for auditing entity creation.
 */
export const AuditCreate = (entityType: string, options?: Partial<AuditMetadata>) =>
  Audit({
    entityType,
    captureRequestBody: true,
    captureResponseBody: true,
    ...options,
  });

/**
 * Decorator for auditing entity reads.
 */
export const AuditRead = (entityType: string, options?: Partial<AuditMetadata>) =>
  Audit({
    entityType,
    captureResponseBody: false,
    ...options,
  });

/**
 * Decorator for auditing entity updates.
 */
export const AuditUpdate = (entityType: string, options?: Partial<AuditMetadata>) =>
  Audit({
    entityType,
    captureRequestBody: true,
    captureResponseBody: true,
    ...options,
  });

/**
 * Decorator for auditing entity deletions.
 */
export const AuditDelete = (entityType: string, options?: Partial<AuditMetadata>) =>
  Audit({
    entityType,
    captureResponseBody: false,
    ...options,
  });
