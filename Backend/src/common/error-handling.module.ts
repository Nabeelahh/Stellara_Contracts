import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { GlobalExceptionFilter } from './exceptions/global-exception.filter';
import { ValidationFilter } from './filters/validation.filter';
import { ErrorResponseInterceptor } from './interceptors/error-response.interceptor';

@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: GlobalExceptionFilter,
    },
    {
      provide: APP_FILTER,
      useClass: ValidationFilter,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ErrorResponseInterceptor,
    },
  ],
  exports: [GlobalExceptionFilter, ValidationFilter, ErrorResponseInterceptor],
})
export class ErrorHandlingModule {}
