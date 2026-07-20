import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { TracingService } from '../services/tracing.service';
import { LoggingService } from '../services/logging.service';
import { MetricsService } from '../services/metrics.service';

/**
 * HTTP Tracing Interceptor
 * Extracts/creates trace IDs, measures request duration, and logs errors.
 * Correlates every request through the `X-Request-ID` / correlation ID that
 * is set by the upstream CorrelationMiddleware.
 */
@Injectable()
export class TracingInterceptor implements NestInterceptor {
  constructor(
    private tracingService: TracingService,
    private loggingService: LoggingService,
    private metricsService: MetricsService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // Use the correlation ID already attached by CorrelationMiddleware, or
    // extract one from the incoming headers via the tracing service.
    const correlationId: string =
      (request as any).correlationId ||
      (request.headers['x-request-id'] as string) ||
      this.metricsService.generateCorrelationId();

    // Extract or create trace context
    const traceContext = this.tracingService.extractTraceContext(
      request.headers as Record<string, string>,
    );

    // Attach both trace context and correlation ID to the request
    (request as any).traceContext = traceContext;
    (request as any).correlationId = correlationId;

    // Propagate correlation ID through the trace context metadata
    this.tracingService.addMetadata(traceContext.traceId, { correlationId });

    // Set response headers with trace ID
    const traceHeaders = this.tracingService.injectTraceContext(traceContext);
    Object.entries(traceHeaders).forEach(([key, value]) => {
      response.setHeader(key, value);
    });

    const startTime = Date.now();
    const requestSize = this.getRequestSize(request);

    this.loggingService.info('HTTP request received', {
      traceId: traceContext.traceId,
      spanId: traceContext.spanId,
      correlationId,
      method: request.method,
      path: request.path,
      url: request.url,
      ip: this.getClientIp(request),
      userAgent: request.get('user-agent'),
      userId: traceContext.userId,
    });

    return next.handle().pipe(
      tap((responseData) => {
        const duration = (Date.now() - startTime) / 1000;
        const responseSize = this.getResponseSize(responseData);

        const statusCode = response.statusCode;
        const route = this.getRouteLabel(request);

        this.metricsService.recordHttpRequest(
          request.method,
          route,
          statusCode,
          duration,
          correlationId,
          requestSize,
          responseSize,
        );

        this.loggingService.info('HTTP request completed', {
          traceId: traceContext.traceId,
          spanId: traceContext.spanId,
          correlationId,
          method: request.method,
          path: request.path,
          statusCode,
          duration,
          requestSize,
          responseSize,
          userId: traceContext.userId,
        });
      }),
      catchError((error) => {
        const duration = (Date.now() - startTime) / 1000;
        const route = this.getRouteLabel(request);

        this.metricsService.recordHttpError(
          request.method,
          route,
          error.name || 'UnknownError',
          correlationId,
        );

        this.loggingService.error('HTTP request error', error, {
          traceId: traceContext.traceId,
          spanId: traceContext.spanId,
          correlationId,
          method: request.method,
          path: request.path,
          statusCode: response.statusCode,
          duration,
          userId: traceContext.userId,
          errorMessage: error.message,
        });

        throw error;
      }),
    );
  }

  private getRequestSize(request: Request): number {
    const contentLength = request.get('content-length');
    return contentLength ? parseInt(contentLength) : 0;
  }

  private getResponseSize(data: any): number {
    if (!data) return 0;
    if (typeof data === 'string') return Buffer.byteLength(data);
    try {
      return Buffer.byteLength(JSON.stringify(data));
    } catch {
      return 0;
    }
  }

  private getClientIp(request: Request): string {
    return (
      (request.get('x-forwarded-for') as string)?.split(',')[0] ||
      request.ip ||
      'unknown'
    );
  }

  private getRouteLabel(request: Request): string {
    const route = (request as any).route?.path || request.path;
    return `${request.method} ${route}`;
  }
}
