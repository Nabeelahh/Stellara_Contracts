import { AUDIT_METADATA_KEY, AuditMetadata, SKIP_AUDIT_KEY } from '../interfaces/audit.interface';
import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Request, Response } from 'express';
import { catchError, tap } from 'rxjs/operators';

import { AsyncContextService } from '../../logging/services/async-context.service';
import { AuditAction } from '@prisma/client';
import { AuditService } from '../audit.service';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  private readonly methodToActionMap: Record<string, AuditAction> = {
    GET: AuditAction.READ,
    POST: AuditAction.CREATE,
    PUT: AuditAction.UPDATE,
    PATCH: AuditAction.UPDATE,
    DELETE: AuditAction.DELETE,
  };

  constructor(
    private readonly auditService: AuditService,
    private readonly asyncContext: AsyncContextService,
    private readonly reflector: Reflector,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Check if audit should be skipped
    const skipAudit = this.reflector.getAllAndOverride<boolean>(SKIP_AUDIT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipAudit) {
      return next.handle();
    }

    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    // Get audit metadata from decorator or infer from request
    const auditMetadata = this.reflector.getAllAndOverride<AuditMetadata>(AUDIT_METADATA_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const startTime = Date.now();
    const method = request.method;
    const path = request.route?.path || request.url;
    const entityType = auditMetadata?.entityType || this.inferEntityType(path);
    const action = auditMetadata?.action || this.getActionFromMethod(method);

    // Extract entity ID from route params
    const entityId = this.extractEntityId(request);

    // Capture request body if configured
    const requestBody = this.shouldCaptureRequestBody(auditMetadata, method)
      ? this.sanitizeRequestBody(request.body, auditMetadata?.sensitiveFields)
      : undefined;

    return next.handle().pipe(
      tap({
        next: async (responseBody) => {
          const duration = Date.now() - startTime;

          // Capture response body if configured
          const capturedResponseBody = this.shouldCaptureResponseBody(auditMetadata, method)
            ? this.limitResponseBodySize(responseBody)
            : undefined;

          await this.auditService.log({
            correlationId: this.asyncContext.getCorrelationId(),
            tenantId: this.asyncContext.getTenantId(),
            userId: this.asyncContext.getUserId(),
            action,
            entityType,
            entityId,
            method,
            path,
            statusCode: response.statusCode,
            ipAddress: this.getClientIp(request),
            userAgent: request.headers['user-agent'],
            requestBody,
            responseBody: capturedResponseBody,
            duration,
          });
        },
      }),
      catchError(async (error) => {
        const duration = Date.now() - startTime;

        await this.auditService.log({
          correlationId: this.asyncContext.getCorrelationId(),
          tenantId: this.asyncContext.getTenantId(),
          userId: this.asyncContext.getUserId(),
          action: AuditAction.ERROR,
          entityType,
          entityId,
          method,
          path,
          statusCode: error.status || 500,
          ipAddress: this.getClientIp(request),
          userAgent: request.headers['user-agent'],
          requestBody,
          duration,
          errorMessage: error.message,
          metadata: {
            errorName: error.name,
            errorStack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
          },
        });

        throw error;
      }),
    );
  }

  private getActionFromMethod(method: string): AuditAction {
    return this.methodToActionMap[method.toUpperCase()] || AuditAction.API_CALL;
  }

  private inferEntityType(path: string): string {
    // Extract entity type from path segments
    // e.g., /api/v1/users/123 -> 'users'
    // e.g., /api/v1/projects/456/milestones -> 'milestones'
    const segments = path.split('/').filter(Boolean);

    // Find the last non-ID segment
    for (let i = segments.length - 1; i >= 0; i--) {
      const segment = segments[i];
      // Skip numeric IDs, UUIDs, and common path prefixes
      if (!this.isId(segment) && !['api', 'v1', 'v2', 'v3'].includes(segment.toLowerCase())) {
        return segment;
      }
    }

    return 'unknown';
  }

  private isId(segment: string): boolean {
    // Check for numeric ID
    if (/^\d+$/.test(segment)) return true;

    // Check for UUID
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
      return true;
    }

    // Check for cuid
    if (/^c[a-z0-9]{24}$/.test(segment)) return true;

    return false;
  }

  private extractEntityId(request: Request): string | undefined {
    // Try common param names for entity ID
    const paramNames = ['id', 'userId', 'projectId', 'entityId'];

    for (const name of paramNames) {
      if (request.params[name]) {
        return request.params[name];
      }
    }

    // Try to extract from path
    const segments = request.url.split('/').filter(Boolean);
    for (let i = segments.length - 1; i >= 0; i--) {
      if (this.isId(segments[i])) {
        return segments[i];
      }
    }

    // For POST, try to get ID from response body (will be captured later)
    return undefined;
  }

  private shouldCaptureRequestBody(metadata: AuditMetadata | undefined, method: string): boolean {
    if (metadata?.captureRequestBody !== undefined) {
      return metadata.captureRequestBody;
    }

    // By default, capture for mutating methods
    return ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase());
  }

  private shouldCaptureResponseBody(metadata: AuditMetadata | undefined, method: string): boolean {
    if (metadata?.captureResponseBody !== undefined) {
      return metadata.captureResponseBody;
    }

    // By default, capture for CREATE and UPDATE
    return ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase());
  }

  private sanitizeRequestBody(
    body: any,
    sensitiveFields?: string[],
  ): Record<string, unknown> | undefined {
    if (!body || typeof body !== 'object') return undefined;

    const defaultSensitive = [
      'password',
      'token',
      'secret',
      'apiKey',
      'refreshToken',
      'accessToken',
    ];
    const fieldsToRedact = [...defaultSensitive, ...(sensitiveFields || [])];

    return this.redactFields(body, fieldsToRedact);
  }

  private redactFields(obj: Record<string, unknown>, fields: string[]): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      const shouldRedact = fields.some((field) => key.toLowerCase().includes(field.toLowerCase()));

      if (shouldRedact) {
        result[key] = '[REDACTED]';
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        result[key] = this.redactFields(value as Record<string, unknown>, fields);
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  private limitResponseBodySize(responseBody: any): Record<string, unknown> | undefined {
    if (!responseBody) return undefined;

    const serialized = JSON.stringify(responseBody);

    // Limit to 10KB to prevent storing huge responses
    if (serialized.length > 10240) {
      return {
        _truncated: true,
        _originalSize: serialized.length,
        _preview: serialized.substring(0, 1000),
      };
    }

    return responseBody;
  }

  private getClientIp(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (request.headers['x-real-ip'] as string) ||
      request.ip ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }
}
