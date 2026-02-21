import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiResponseDto } from '../dtos/api-response.dto';

/**
 * Wraps every successful controller return value in the ApiResponseDto envelope:
 *
 *   { success: true, timestamp: "…", data: <original value> }
 *
 * If the controller already returns { data, meta } (paginated response),
 * those fields are lifted up rather than nested again.
 *
 * Registered globally in AppModule via APP_INTERCEPTOR.
 */
@Injectable()
export class ResponseTransformInterceptor<T>
  implements NestInterceptor<T, ApiResponseDto<T>>
{
  intercept(
    _context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<ApiResponseDto<T>> {
    return next.handle().pipe(
      map((value) => {
        // Already-wrapped paginated response: { data: T[], meta: PaginationMetaDto }
        if (
          value !== null &&
          typeof value === 'object' &&
          'data' in (value as object) &&
          'meta' in (value as object)
        ) {
          const v = value as { data: T; meta: unknown };
          return {
            success:   true,
            timestamp: new Date().toISOString(),
            data:      v.data,
            meta:      v.meta,
          } as ApiResponseDto<T>;
        }

        return {
          success:   true,
          timestamp: new Date().toISOString(),
          data:      value,
        } as ApiResponseDto<T>;
      }),
    );
  }
}