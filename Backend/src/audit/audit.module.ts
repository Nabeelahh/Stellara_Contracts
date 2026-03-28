import { Global, MiddlewareConsumer, Module, RequestMethod } from '@nestjs/common';

import { AuditContextMiddleware } from './middleware/audit-context.middleware';
import { AuditController } from './audit.controller';
import { AuditInterceptor } from './interceptors/audit.interceptor';
import { AuditRetentionService } from './audit-retention.service';
import { AuditService } from './audit.service';
import { DatabaseModule } from '../database.module';
import { ScheduleModule } from '@nestjs/schedule';

@Global()
@Module({
  imports: [
    DatabaseModule,
    ScheduleModule.forRoot(), // Required for retention policy cron jobs
  ],
  controllers: [AuditController],
  providers: [AuditService, AuditRetentionService, AuditInterceptor, AuditContextMiddleware],
  exports: [AuditService, AuditRetentionService, AuditInterceptor, AuditContextMiddleware],
})
export class AuditModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AuditContextMiddleware).forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
