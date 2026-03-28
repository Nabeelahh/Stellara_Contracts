import { Module } from '@nestjs/common';
import { NotificationModule } from '../notification/notification.module';
import { RedisModule } from '../redis/redis.module';
import { TenantQuotaMiddleware } from './tenant-quota.middleware';
import { TenantQuotaService } from './quota.service';

@Module({
  imports: [RedisModule, NotificationModule],
  providers: [TenantQuotaService, TenantQuotaMiddleware],
  exports: [TenantQuotaService, TenantQuotaMiddleware],
})
export class QuotaModule {}
