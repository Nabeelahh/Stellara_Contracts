import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RateLimitService } from '../services/rate-limit.service';
import { RateLimitError } from '../../common/exceptions/api-error.exception';

export const RATE_LIMIT_KEY = 'rate_limit';

export interface RateLimitOptions {
  limit: number;
  windowSeconds: number;
  keyPrefix?: string;
}

export const RateLimit = (options: RateLimitOptions) => {
  return (
    target: any,
    propertyKey?: string,
    descriptor?: PropertyDescriptor,
  ) => {
    if (propertyKey && descriptor) {
      Reflect.defineMetadata(RATE_LIMIT_KEY, options, descriptor.value);
      return descriptor;
    }
    Reflect.defineMetadata(RATE_LIMIT_KEY, options, target);
    return target;
  };
};

/**
 * Guard that enforces per-IP rate limits on decorated endpoints.
 *
 * Throws `RateLimitError` (typed `ApiError`) so the `HttpExceptionFilter`
 * renders the standard error envelope with errorCode `RATE_LIMIT_EXCEEDED`.
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly rateLimitService: RateLimitService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const options = this.reflector.get<RateLimitOptions>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );

    if (!options) {
      return true; // No rate limit configured
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Get client IP
    const ip = request.ip || request.connection.remoteAddress;

    // Generate rate limit key
    const keyPrefix = options.keyPrefix || context.getHandler().name;
    const key = this.rateLimitService.generateKeyForIp(ip, keyPrefix);

    // Check rate limit
    const result = await this.rateLimitService.checkRateLimit(
      key,
      options.limit,
      options.windowSeconds,
    );

    // Set informational rate limit headers
    response.setHeader('X-RateLimit-Limit', options.limit);
    response.setHeader('X-RateLimit-Remaining', result.remaining);
    response.setHeader('X-RateLimit-Reset', result.resetAt.toISOString());

    if (!result.allowed) {
      throw new RateLimitError(result.resetAt);
    }

    return true;
  }
}
