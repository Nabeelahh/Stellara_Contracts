import { HttpException, HttpStatus } from '@nestjs/common';

export interface ErrorDetail {
  field?: string;
  code: string;
  message: string;
  timestamp: string;
  path?: string;
}

export interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: ErrorDetail[];
    timestamp: string;
    path?: string;
    requestId?: string;
  };
}

export abstract class BaseHttpException extends HttpException {
  public readonly timestamp: string;
  public readonly requestId: string;
  public readonly path?: string;

  constructor(
    message: string,
    public readonly code: string,
    public readonly httpStatus: HttpStatus,
    public readonly details?: ErrorDetail[],
    path?: string,
  ) {
    super({
      message,
      statusCode: httpStatus,
    });

    this.timestamp = new Date().toISOString();
    this.requestId = this.generateRequestId();
    this.path = path;
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getResponse(): ErrorResponse {
    return {
      success: false,
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
        timestamp: this.timestamp,
        path: this.path,
        requestId: this.requestId,
      },
    };
  }
}

export class ValidationException extends BaseHttpException {
  constructor(
    message: string,
    code: string = 'VALIDATION_ERROR',
    details?: ErrorDetail[],
    path?: string,
  ) {
    super(message, code, HttpStatus.BAD_REQUEST, details, path);
  }
}

export class AuthenticationException extends BaseHttpException {
  constructor(
    message: string = 'Authentication failed',
    code: string = 'AUTHENTICATION_ERROR',
    details?: ErrorDetail[],
  ) {
    super(message, code, HttpStatus.UNAUTHORIZED, details);
  }
}

export class AuthorizationException extends BaseHttpException {
  constructor(
    message: string = 'Insufficient permissions',
    code: string = 'AUTHORIZATION_ERROR',
    details?: ErrorDetail[],
  ) {
    super(message, code, HttpStatus.FORBIDDEN, details);
  }
}

export class ResourceNotFoundException extends BaseHttpException {
  constructor(resource: string, identifier?: string, path?: string) {
    const message = identifier
      ? `${resource} with identifier '${identifier}' not found`
      : `${resource} not found`;

    super(message, 'RESOURCE_NOT_FOUND', HttpStatus.NOT_FOUND, undefined, path);
  }
}

export class ResourceConflictException extends BaseHttpException {
  constructor(
    message: string,
    code: string = 'RESOURCE_CONFLICT',
    details?: ErrorDetail[],
    path?: string,
  ) {
    super(message, code, HttpStatus.CONFLICT, details, path);
  }
}

export class RateLimitException extends BaseHttpException {
  constructor(
    message: string = 'Rate limit exceeded',
    code: string = 'RATE_LIMIT_EXCEEDED',
    details?: ErrorDetail[],
    retryAfter?: number,
  ) {
    super(message, code, HttpStatus.TOO_MANY_REQUESTS, details);
  }
}

export class InternalServerException extends BaseHttpException {
  constructor(
    message: string = 'Internal server error',
    code: string = 'INTERNAL_SERVER_ERROR',
    details?: ErrorDetail[],
  ) {
    super(message, code, HttpStatus.INTERNAL_SERVER_ERROR, details);
  }
}

export class ServiceUnavailableException extends BaseHttpException {
  constructor(
    message: string = 'Service temporarily unavailable',
    code: string = 'SERVICE_UNAVAILABLE',
    details?: ErrorDetail[],
  ) {
    super(message, code, HttpStatus.SERVICE_UNAVAILABLE, details);
  }
}

export class BusinessLogicException extends BaseHttpException {
  constructor(
    message: string,
    code: string = 'BUSINESS_LOGIC_ERROR',
    details?: ErrorDetail[],
    path?: string,
  ) {
    super(message, code, HttpStatus.UNPROCESSABLE_ENTITY, details, path);
  }
}

export class DatabaseException extends BaseHttpException {
  constructor(
    message: string = 'Database operation failed',
    code: string = 'DATABASE_ERROR',
    details?: ErrorDetail[],
  ) {
    super(message, code, HttpStatus.INTERNAL_SERVER_ERROR, details);
  }
}

export class ExternalServiceException extends BaseHttpException {
  constructor(
    service: string,
    message: string,
    code: string = 'EXTERNAL_SERVICE_ERROR',
    details?: ErrorDetail[],
  ) {
    super(`${service}: ${message}`, code, HttpStatus.BAD_GATEWAY, details);
  }
}
