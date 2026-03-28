import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ApiVersioningInterceptor } from './versioning.interceptor';
import { ApiV1Module } from './v1/api-v1.module';
import { ApiV2Module } from './v2/api-v2.module';

@Module({
  imports: [ApiV1Module, ApiV2Module],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: ApiVersioningInterceptor,
    },
  ],
  exports: [ApiV1Module, ApiV2Module],
})
export class ApiVersioningModule {}
