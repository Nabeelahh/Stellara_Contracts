import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

import { AsyncContextService } from '../../logging/services/async-context.service';

/**
 * Middleware to capture user context and store it in async context
 * for use by the audit logging system.
 */
@Injectable()
export class AuditContextMiddleware implements NestMiddleware {
  constructor(private readonly asyncContext: AsyncContextService) {}

  use(req: Request, res: Response, next: NextFunction): void {
    // Set IP address in async context
    const ipAddress = this.getClientIp(req);
    this.asyncContext.set('ipAddress', ipAddress);

    // Set user agent
    const userAgent = req.headers['user-agent'] || 'unknown';
    this.asyncContext.set('userAgent', userAgent);

    // User ID and tenant ID are typically set after authentication
    // by the auth guard or a subsequent middleware

    // Check for user in request (set by auth middleware/guard)
    if ((req as any).user) {
      const user = (req as any).user;
      if (user.id) {
        this.asyncContext.setUserId(user.id);
      }
      if (user.tenantId) {
        this.asyncContext.setTenantId(user.tenantId);
      }
    }

    // Also check for tenant ID in headers (for multi-tenant scenarios)
    const tenantIdHeader = req.headers['x-tenant-id'] as string;
    if (tenantIdHeader && !this.asyncContext.getTenantId()) {
      this.asyncContext.setTenantId(tenantIdHeader);
    }

    next();
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
