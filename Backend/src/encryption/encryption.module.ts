import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EncryptionService } from './services/encryption.service';
import { EncryptionInterceptor } from './interceptors/encryption.interceptor';
import { EncryptionGuard } from './guards/encryption.guard';
import { APP_INTERCEPTOR } from '@nestjs/core';

@Module({
  imports: [ConfigModule],
  providers: [
    EncryptionService,
    EncryptionInterceptor,
    EncryptionGuard,
    {
      provide: APP_INTERCEPTOR,
      useClass: EncryptionInterceptor,
    },
  ],
  exports: [EncryptionService, EncryptionInterceptor, EncryptionGuard],
})
export class EncryptionModule {}
