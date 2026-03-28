import { Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { TenantQuotaService } from './quota.service';

@Injectable()
export class TenantQuotaMiddleware implements NestMiddleware {
  constructor(private readonly quotaService: TenantQuotaService) {}

  async use(req: Request, _res: Response, next: NextFunction) {
    // Tenant is expected from header/query for SaaS-style multi-tenancy.
    const tenantId = this.quotaService.getTenantIdFromRequest(req);
    if (!tenantId) return next();

    try {
      await this.quotaService.consumeApiCallOrThrow(tenantId);
      return next();
    } catch (err) {
      return next(err);
    }
  }
}
