import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuditModule } from '../audit/audit.module';
import { AuthModule } from '../auth/auth.module';
import { GdprController, AdminGdprController } from './controllers/gdpr.controller';
import { DataExportService } from './services/data-export.service';
import { DataDeletionService } from './services/data-deletion.service';
import { ConsentManagementService } from './services/consent-management.service';
import { DataRetentionService } from './services/data-retention.service';
import { Consent } from './entities/consent.entity';
// Entities from auth/audit used by GDPR services
import { User } from '../auth/entities/user.entity';
import { WalletBinding } from '../auth/entities/wallet-binding.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { ApiToken } from '../auth/entities/api-token.entity';
import { AuditLog } from '../audit/audit.entity';

@Module({
  imports: [
    // Register only GDPR-specific Consent repository plus any other repositories
    // used directly by GDPR services. Authenticaton entities are pulled in
    // so the DataExportService and DataDeletionService can inject their
    // repositories without relying on AuthModule to export them.
    TypeOrmModule.forFeature([
      Consent,
      User,
      WalletBinding,
      RefreshToken,
      ApiToken,
      AuditLog,
    ]),
    AuditModule,
    AuthModule,
  ],
  controllers: [GdprController, AdminGdprController],
  providers: [
    DataExportService,
    DataDeletionService,
    ConsentManagementService,
    DataRetentionService,
  ],
  exports: [
    DataExportService,
    DataDeletionService,
    ConsentManagementService,
    DataRetentionService,
  ],
})
export class GdprModule {}