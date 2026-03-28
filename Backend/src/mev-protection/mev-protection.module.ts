import { Module } from '@nestjs/common';
import { MEVProtectionController } from './mev-protection.controller';
import { CommitRevealService } from './services/commit-reveal.service';
import { ThresholdEncryptionService } from './services/threshold-encryption.service';
import { IntelligentOrderRouter } from './services/intelligent-order-router.service';

@Module({
  controllers: [MEVProtectionController],
  providers: [
    CommitRevealService,
    ThresholdEncryptionService,
    IntelligentOrderRouter,
  ],
  exports: [
    CommitRevealService,
    ThresholdEncryptionService,
    IntelligentOrderRouter,
  ],
})
export class MEVProtectionModule {}
