import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { StructuredLogger } from './structured-logger.service';
import { ErrorTrackingService, ErrorSeverity } from './error-tracking.service';
import { MetricsService } from './metrics.service';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new StructuredLogger(AllExceptionsFilter.name);

  constructor(
    private readonly errorTracker: ErrorTrackingService,
    private readonly metrics: MetricsService,
  ) {}

  async catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.getResponse()
        : (exception as any).message || 'Internal server error';

    const severity = status >= 500 ? ErrorSeverity.HIGH : ErrorSeverity.MEDIUM;
    if (status === 500) {
      // escalate to critical for tracking
      this.metrics.incrementError('critical', 'http');
    } else {
      this.metrics.incrementError(severity, 'http');
    }

    // structured log
    this.logger.error(
      message,
      (exception as any).stack,
      AllExceptionsFilter.name,
    );

    await this.errorTracker.track({
      message: String(message),
      stack: (exception as any).stack,
      severity,
      category: 'http',
    });

    // maintain default response structure
    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}
