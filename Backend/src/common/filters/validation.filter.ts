import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { ValidationError } from 'class-validator';
import { Request, Response } from 'express';
import { ValidationException } from '../exceptions/http.exception';
import { ERROR_CODES } from '../exceptions/error-codes';

@Catch(ValidationError)
export class ValidationFilter implements ExceptionFilter {
  private readonly logger = new Logger(ValidationFilter.name);

  catch(exception: ValidationError, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // Format validation errors
    const errors = this.formatValidationErrors(exception);

    const validationException = new ValidationException(
      'Validation failed',
      ERROR_CODES.VALIDATION_FAILED,
      errors,
      request.url,
    );

    response.status(validationException.httpStatus).json(validationException.getResponse());

    this.logger.warn(`Validation failed: ${JSON.stringify(errors)}`, {
      requestId: this.getRequestId(request),
      url: request.url,
      method: request.method,
      errors,
    });
  }

  private formatValidationErrors(validationErrors: ValidationError): any[] {
    return validationErrors.map((error) => ({
      field: error.property,
      code: this.getValidationErrorCode(error),
      message: this.getValidationErrorMessage(error),
      value: error.value,
      constraints: Object.entries(error.constraints || {}).map(([key, message]) => ({
        rule: key,
        message: message as string,
      })),
    }));
  }

  private getValidationErrorCode(error: ValidationError): string {
    const constraints = error.constraints || {};
    const firstConstraint = Object.keys(constraints)[0];

    const errorCodeMap = {
      isEmail: ERROR_CODES.INVALID_FIELD_VALUE,
      isString: ERROR_CODES.INVALID_FIELD_VALUE,
      isNumber: ERROR_CODES.INVALID_FIELD_VALUE,
      isBoolean: ERROR_CODES.INVALID_FIELD_VALUE,
      isArray: ERROR_CODES.INVALID_FIELD_VALUE,
      isNotEmpty: ERROR_CODES.MISSING_REQUIRED_FIELD,
      minLength: ERROR_CODES.VALIDATION_CONSTRAINT_VIOLATION,
      maxLength: ERROR_CODES.VALIDATION_CONSTRAINT_VIOLATION,
      min: ERROR_CODES.VALIDATION_CONSTRAINT_VIOLATION,
      max: ERROR_CODES.VALIDATION_CONSTRAINT_VIOLATION,
      matches: ERROR_CODES.INVALID_INPUT_FORMAT,
      isEmail: ERROR_CODES.INVALID_FIELD_VALUE,
      isUrl: ERROR_CODES.INVALID_INPUT_FORMAT,
      isDate: ERROR_CODES.INVALID_FIELD_VALUE,
      isEnum: ERROR_CODES.INVALID_FIELD_VALUE,
    };

    return errorCodeMap[firstConstraint] || ERROR_CODES.VALIDATION_FAILED;
  }

  private getValidationErrorMessage(error: ValidationError): string {
    const constraints = error.constraints || {};
    const firstConstraint = Object.keys(constraints)[0];

    if (constraints[firstConstraint]) {
      return constraints[firstConstraint] as string;
    }

    // Default messages based on property
    const defaultMessageMap = {
      email: 'Invalid email format',
      password: 'Password does not meet requirements',
      name: 'Name is required',
      amount: 'Invalid amount',
      address: 'Invalid address format',
    };

    return defaultMessageMap[error.property] || 'Invalid value';
  }

  private getRequestId(request: Request): string {
    return (
      request.headers['x-request-id'] ||
      request.headers['request-id'] ||
      `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    );
  }
}
