import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { BaseHttpException, ErrorResponse } from './http.exception';
import { ERROR_CODES, HTTP_STATUS_MAPPING } from './error-codes';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  constructor(private readonly configService: ConfigService) {
    super();
  }

  catch(exception: unknown, host: ArgumentsHost): ErrorResponse {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let errorResponse: ErrorResponse;
    let httpStatus: HttpStatus;

    if (exception instanceof BaseHttpException) {
      // Handle our custom HTTP exceptions
      errorResponse = exception.getResponse();
      httpStatus = exception.httpStatus;

      this.logError(exception, request, 'Custom HTTP Exception');
    } else if (exception instanceof HttpException) {
      // Handle NestJS HTTP exceptions
      const status = exception.getStatus();
      const response = exception.getResponse();

      errorResponse = {
        success: false,
        error: {
          code: this.getErrorCodeFromStatus(status),
          message: exception.message,
          timestamp: new Date().toISOString(),
          path: request.url,
          requestId: this.getRequestId(request),
          ...(typeof response === 'object' && response !== null ? { details: response } : {}),
        },
      };

      httpStatus = status;

      this.logError(exception, request, 'NestJS HTTP Exception');
    } else if (exception instanceof Error) {
      // Handle generic errors
      const isProduction = this.configService.get('NODE_ENV') === 'production';

      errorResponse = {
        success: false,
        error: {
          code: ERROR_CODES.INTERNAL_SERVER_ERROR,
          message: isProduction ? 'Internal server error' : exception.message,
          timestamp: new Date().toISOString(),
          path: request.url,
          requestId: this.getRequestId(request),
          ...(isProduction
            ? {}
            : {
                details: [
                  {
                    field: 'stack',
                    code: 'STACK_TRACE',
                    message: exception.stack,
                    timestamp: new Date().toISOString(),
                  },
                ],
              }),
        },
      };

      httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;

      this.logError(exception, request, 'Generic Error');
    } else {
      // Handle unknown exceptions
      const isProduction = this.configService.get('NODE_ENV') === 'production';

      errorResponse = {
        success: false,
        error: {
          code: ERROR_CODES.INTERNAL_SERVER_ERROR,
          message: isProduction ? 'Internal server error' : 'Unknown error occurred',
          timestamp: new Date().toISOString(),
          path: request.url,
          requestId: this.getRequestId(request),
        },
      };

      httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;

      this.logError(exception, request, 'Unknown Exception');
    }

    // Add security headers
    this.addSecurityHeaders(response);

    // Send error response
    response.status(httpStatus).json(errorResponse);
  }

  private addSecurityHeaders(response: Response): void {
    // Prevent content type sniffing
    response.setHeader('X-Content-Type-Options', 'nosniff');

    // Prevent clickjacking
    response.setHeader('X-Frame-Options', 'DENY');

    // Prevent XSS
    response.setHeader('X-XSS-Protection', '1; mode=block');

    // HSTS
    if (this.configService.get('NODE_ENV') === 'production') {
      response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    // CORS (if not handled by CORS middleware)
    response.setHeader(
      'Access-Control-Allow-Origin',
      this.configService.get('ALLOWED_ORIGINS', '*'),
    );
    response.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Request-ID');
  }

  private getErrorCodeFromStatus(status: number): string {
    // Find error code by HTTP status
    for (const [code, mappedStatus] of Object.entries(HTTP_STATUS_MAPPING)) {
      if (mappedStatus === status) {
        return code;
      }
    }
    return ERROR_CODES.INTERNAL_SERVER_ERROR;
  }

  private getRequestId(request: Request): string {
    // Try to get request ID from header or generate new one
    return (
      request.headers['x-request-id'] ||
      request.headers['request-id'] ||
      `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    );
  }

  private logError(exception: Error, request: Request, type: string): void {
    const requestId = this.getRequestId(request);
    const userId = request.user?.id || 'anonymous';
    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'];

    const logData = {
      requestId,
      userId,
      ip,
      userAgent,
      url: request.url,
      method: request.method,
      type,
      message: exception.message,
      stack: exception.stack,
      timestamp: new Date().toISOString(),
    };

    // Log based on error severity
    const httpStatus =
      exception instanceof BaseHttpException
        ? exception.httpStatus
        : HttpStatus.INTERNAL_SERVER_ERROR;

    if (httpStatus >= 500) {
      this.logger.error(`[${type}] ${exception.message}`, logData);
    } else if (httpStatus >= 400) {
      this.logger.warn(`[${type}] ${exception.message}`, logData);
    } else {
      this.logger.log(`[${type}] ${exception.message}`, logData);
    }

    // In production, send to external monitoring
    if (this.configService.get('NODE_ENV') === 'production') {
      this.sendToMonitoring(logData, exception);
    }
  }

  private getClientIP(request: Request): string {
    return (
      request.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      request.headers['x-real-ip'] ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      '127.0.0.1'
    );
  }

  private sendToMonitoring(logData: any, exception: Error): void {
    // Send to external monitoring services like Sentry, DataDog, etc.
    // This would be implemented based on your monitoring setup

    try {
      // Example: Send to Sentry
      if (process.env.SENTRY_DSN) {
        // Sentry.captureException(exception, {
        //   user: { id: logData.userId },
        //   tags: { requestId: logData.requestId },
        //   extra: logData,
        // });
      }
    } catch (error) {
      this.logger.error('Failed to send to monitoring service:', error);
    }
  }
}
