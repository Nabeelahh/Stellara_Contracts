import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { SKIP_RATE_LIMIT } from '../decorators/skip-rate-limit.decorator';
import { RateLimitService } from '../../rate-limiting/rate-limit.service';

@Injectable()
export class UserThrottlerGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimitService: RateLimitService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') {
      return true;
    }

    const skipRateLimit = this.reflector.getAllAndOverride<boolean>(SKIP_RATE_LIMIT, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipRateLimit) {
      return true;
    }

    const req = context.switchToHttp().getRequest<Request>();
    await this.rateLimitService.acquire(req);

    return true;
  }
}
