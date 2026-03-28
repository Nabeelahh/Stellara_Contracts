import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  LoggerService,
  Inject,
  Optional,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { AsyncContextService } from '../services/async-context.service';
import { PerformanceTrace } from '../interfaces/logger.interface';

@Injectable()
export class RequestLoggingInterceptor implements NestInterceptor {
  private readonly contextName = 'HttpRequest';

  constructor(
    private readonly asyncContext: AsyncContextService,
    @Optional() @Inject('LOGGER_SERVICE') private readonly logger: LoggerService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const ctx = context.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    const startTime = Date.now();
    const startHrTime = process.hrtime.bigint();

    // Get context from async context
    const correlationId = this.asyncContext.getCorrelationId();
    const userId = this.asyncContext.getUserId();
    const tenantId = this.asyncContext.getTenantId();
    const requestId = this.asyncContext.getRequestId();

    // Create trace for this request
    const trace: PerformanceTrace = {
      name: `${request.method} ${request.route?.path || request.url}`,
      startTime,
      metadata: {
        method: request.method,
        url: request.url,
        path: request.route?.path,
        query: request.query,
        ip: this.getClientIp(request),
        userAgent: request.headers['user-agent'],
        contentLength: request.headers['content-length'],
        contentType: request.headers['content-type'],
      },
    };

    // Log incoming request
    this.logRequest(request, {
      correlationId,
      userId,
      tenantId,
      requestId,
      trace,
    });

    return next.handle().pipe(
      tap({
        next: (data) => {
          const endTime = Date.now();
          const endHrTime = process.hrtime.bigint();
          const durationMs = endTime - startTime;
          const durationNs = Number(endHrTime - startHrTime) / 1_000_000;

          // Update trace with end time
          trace.endTime = endTime;
          trace.duration = durationMs;

          // Log successful response
          this.logResponse(response, {
            correlationId,
            userId,
            tenantId,
            requestId,
            trace,
            durationMs,
            durationNs,
            statusCode: response.statusCode,
            data,
          });
        },
      }),
      catchError((error) => {
        const endTime = Date.now();
        const durationMs = endTime - startTime;

        // Update trace with end time
        trace.endTime = endTime;
        trace.duration = durationMs;

        // Log error response
        this.logError(error, {
          correlationId,
          userId,
          tenantId,
          requestId,
          trace,
          durationMs,
          statusCode: error.status || 500,
        });

        throw error;
      }),
    );
  }

  private logRequest(request: Request, context: any): void {
    const logData = {
      type: 'request',
      method: request.method,
      url: request.url,
      path: request.route?.path || request.path,
      query: Object.keys(request.query).length > 0 ? request.query : undefined,
      ip: context.trace.metadata.ip,
      userAgent: context.trace.metadata.userAgent,
      correlationId: context.correlationId,
      userId: context.userId,
      tenantId: context.tenantId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
    };

    if (this.logger) {
      this.logger.log({
        msg: `Incoming ${request.method} ${request.url}`,
        ...logData,
      });
    } else {
      console.log(JSON.stringify(logData));
    }
  }

  private logResponse(response: Response, context: any): void {
    const logData = {
      type: 'response',
      method: context.trace.metadata.method,
      url: context.trace.metadata.url,
      path: context.trace.name,
      statusCode: context.statusCode,
      durationMs: context.durationMs,
      durationNs: context.durationNs?.toFixed(3),
      correlationId: context.correlationId,
      userId: context.userId,
      tenantId: context.tenantId,
      requestId: context.requestId,
      contentLength: response.getHeader('content-length'),
      timestamp: new Date().toISOString(),
    };

    if (this.logger) {
      this.logger.log({
        msg: `Outgoing ${context.trace.metadata.method} ${context.trace.metadata.url} ${context.statusCode} ${context.durationMs}ms`,
        ...logData,
      });
    } else {
      console.log(JSON.stringify(logData));
    }
  }

  private logError(error: any, context: any): void {
    const logData = {
      type: 'error',
      method: context.trace.metadata.method,
      url: context.trace.metadata.url,
      path: context.trace.name,
      statusCode: context.statusCode,
      durationMs: context.durationMs,
      correlationId: context.correlationId,
      userId: context.userId,
      tenantId: context.tenantId,
      requestId: context.requestId,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: error.code,
      },
      timestamp: new Date().toISOString(),
    };

    if (this.logger) {
      this.logger.error({
        msg: `Error ${context.trace.metadata.method} ${context.trace.metadata.url} ${context.statusCode} ${context.durationMs}ms - ${error.message}`,
        ...logData,
      });
    } else {
      console.error(JSON.stringify(logData));
    }
  }

  private getClientIp(request: Request): string {
    const forwardedFor = request.headers['x-forwarded-for'];
    const forwardedForStr = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;

    return (
      forwardedForStr?.split(',')[0]?.trim() ||
      request.headers['x-real-ip']?.toString() ||
      request.socket?.remoteAddress ||
      '127.0.0.1'
    );
  }
}
