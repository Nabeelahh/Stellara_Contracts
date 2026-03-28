import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { BaseHttpException, ErrorResponse } from '../exceptions/http.exception';

@Injectable()
export class ErrorResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();

    return next.handle().pipe(
      map((data) => {
        // Wrap successful responses
        return {
          success: true,
          data,
          timestamp: new Date().toISOString(),
          requestId: this.getRequestId(request),
        };
      }),
      catchError((error) => {
        // Handle errors and format them consistently
        if (error instanceof BaseHttpException) {
          throw error; // Will be caught by global filter
        }

        // Convert other errors to BaseHttpException
        const httpException = new HttpException(
          error.message,
          error.status || HttpStatus.INTERNAL_SERVER_ERROR,
        );

        throw httpException;
      }),
    );
  }

  private getRequestId(request: any): string {
    return (
      request.headers['x-request-id'] ||
      request.headers['request-id'] ||
      `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    );
  }
}
