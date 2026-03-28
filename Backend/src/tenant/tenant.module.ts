import { Module } from '@nestjs/common';
import { TenantService } from './tenant.service';
import { TenantIsolationValidator } from './tenant-isolation-validator.service';
import { TenantController } from './tenant.controller';
import { DatabaseModule } from '../database.module';
import { NotificationModule } from '../notification/notification.module';
import { QuotaModule } from '../quota/quota.module';
import { AdvancedCacheModule } from '../cache/advanced-cache.module';
import { RabbitmqModule } from '../messaging/rabbitmq/rabbitmq.module';

@Module({
  imports: [DatabaseModule, NotificationModule, QuotaModule, AdvancedCacheModule, RabbitmqModule],
  controllers: [TenantController],
  providers: [TenantService, TenantIsolationValidator],
  exports: [TenantService, TenantIsolationValidator],
})
export class TenantModule {}
