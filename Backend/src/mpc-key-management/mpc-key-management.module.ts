import { Module } from '@nestjs/common';
import { MPCKeysController } from './mpc-key-management.controller';
import { MPCKeysService } from './services/mpc-keys.service';
import { HSMIntegrationService } from './services/hsm-integration.service';

@Module({
  controllers: [MPCKeysController],
  providers: [MPCKeysService, HSMIntegrationService],
  exports: [MPCKeysService, HSMIntegrationService],
})
export class MPCKeysModule {}
