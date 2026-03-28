import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { User } from '../auth/entities/user.entity';
import { TransactionRecord } from '../contract-interaction/entities/transaction-record.entity';
import { ContractMetadata } from '../contract-interaction/entities/contract-metadata.entity';
import { Workflow } from '../workflow/entities/workflow.entity';
import { AuditLog } from '../audit/audit.entity';
import { Consent } from '../gdpr/entities/consent.entity';
import { VoiceJob } from '../voice/entities/voice-job.entity';
import { AuditModule } from '../audit/audit.module';
import { SearchModule } from '../search/search.module';
import { ContractInteractionModule } from '../contract-interaction/contract-interaction.module';
import { AdvancedCacheModule } from '../cache/advanced-cache.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      TransactionRecord,
      ContractMetadata,
      Workflow,
      AuditLog,
      Consent,
      VoiceJob,
    ]),
    ConfigModule,
    AuditModule,
    SearchModule,
    ContractInteractionModule,
    AdvancedCacheModule,
  ],
  controllers: [AdminController],
  providers: [AdminService],
  exports: [AdminService],
})
export class AdminModule {}
