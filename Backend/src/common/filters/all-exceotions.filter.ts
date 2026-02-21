import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ErrorResponseDto } from '../dtos/api-response.dto';

/**
 * Catches every thrown exception (HTTP or otherwise) and converts it
 * into the typed ErrorResponseDto envelope so every error looks the same.
 *
 * Registered globally in AppModule via APP_FILTER.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx      = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request  = ctx.getRequest<Request>();

    let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    let message    = 'Internal server error';
    let error      = 'INTERNAL_SERVER_ERROR';
    let details: string[] | undefined;

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const res  = exception.getResponse();

      if (typeof res === 'object' && res !== null) {
        const r = res as Record<string, unknown>;

        // NestJS ValidationPipe sends message as an array of per-field errors
        if (Array.isArray(r['message'])) {
          details = r['message'] as string[];
          message = 'Validation failed';
        } else {
          message = String(r['message'] ?? exception.message);
        }
        error = String(r['error'] ?? HttpStatus[statusCode]);
      } else {
        message = String(res);
        error   = HttpStatus[statusCode] ?? 'HTTP_EXCEPTION';
      }
    } else if (exception instanceof Error) {
      // Log stack for unknown errors — never expose it to clients
      this.logger.error(
        `Unhandled exception on ${request.method} ${request.url}: ${exception.message}`,
        exception.stack,
      );
    }

    const body: ErrorResponseDto = {
      success:   false,
      statusCode,
      error,
      message,
      timestamp: new Date().toISOString(),
      ...(details ? { details } : {}),
    };

    response.status(statusCode).json(body);
  }
}