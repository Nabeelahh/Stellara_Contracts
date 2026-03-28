// src/secrets-management/secrets-management.module.ts
import { Module } from '@nestjs/common';
import { SecretsManagementService } from './secrets-management.service';
import { SecretsManagementController } from './secrets-management.controller';
import { SecretRotationService } from './secret-rotation.service';
import { SecretAccessLoggerService } from './secret-access-logger.service';
import { ConfigWithSecretsService } from './config-with-secrets.service';

@Module({
  providers: [
    SecretsManagementService,
    SecretRotationService,
    SecretAccessLoggerService,
    ConfigWithSecretsService,
  ],
  controllers: [SecretsManagementController],
  exports: [
    SecretsManagementService,
    ConfigWithSecretsService,
  ],
})
export class SecretsManagementModule {}