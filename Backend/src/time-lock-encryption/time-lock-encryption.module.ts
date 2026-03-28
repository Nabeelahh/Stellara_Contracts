import { Module } from '@nestjs/common';
import { TimeLockEncryptionController } from './controllers/time-lock-encryption.controller';
import { TimeLockEncryptionService } from './services/time-lock-encryption.service';
import { VDFService } from './services/vdf.service';
import { RSATimeLockService } from './services/rsa-time-lock.service';
import { SequentialComputationService } from './services/sequential-computation.service';
import { ParallelResistanceService } from './services/parallel-resistance.service';
import { PublicVerifiabilityService } from './services/public-verifiability.service';
import { SmartContractIntegrationService } from './services/smart-contract-integration.service';
import { TimeLockUseCasesService } from './services/time-lock-use-cases.service';

@Module({
  controllers: [TimeLockEncryptionController],
  providers: [
    TimeLockEncryptionService,
    VDFService,
    RSATimeLockService,
    SequentialComputationService,
    ParallelResistanceService,
    PublicVerifiabilityService,
    SmartContractIntegrationService,
    TimeLockUseCasesService,
  ],
  exports: [
    TimeLockEncryptionService,
    VDFService,
    RSATimeLockService,
    SequentialComputationService,
    ParallelResistanceService,
    PublicVerifiabilityService,
    SmartContractIntegrationService,
    TimeLockUseCasesService,
  ],
})
export class TimeLockEncryptionModule {}
