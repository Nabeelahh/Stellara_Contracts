import { AbiRegistryModule } from './abi-registry/abi-registry.module';
import { ExperimentsModule } from './experiments/experiments.module';
import { AnalyticsModule } from './analytics/analytics.module';

import { AdminModule } from './admin/admin.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { BackupModule } from './backup/backup.module';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database.module';
import { DocsController } from './docs/docs.controller';
import { ErrorHandlingModule } from './common/error-handling.module';
import { IndexAnalysisModule } from './index-analysis/index-analysis.module';
import { LifecycleModule } from './lifecycle/lifecycle.module';
import { LoggingModule } from './logging/logging.module';
import { Module } from '@nestjs/common';
import { PaymentModule } from './payment/payment.module';
import { PrismaModule } from './prisma.module';
import { QuotaModule } from './quota/quota.module';
import { RabbitmqModule } from './messaging/rabbitmq/rabbitmq.module';
import { RateLimitModule } from './rate-limiting/rate-limit.module';
import { RedisModule } from './redis/redis.module';
import { ReputationModule } from './reputation/reputation.module';
import { ScheduleModule } from '@nestjs/schedule';
import { SessionModule } from './sessions/session.module';
import { TenantModule } from './tenant/tenant.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import { UserController } from './user.controller';
import { WebhooksModule } from './webhooks/webhooks.module';
import { WebsocketModule } from './websocket/websocket.module';
import { validateEnv } from './config/env.validation';

import { SupportModule } from './support/support.module';
import { MultisigModule } from './multisig/multisig.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validate: validateEnv,
    }),
    ScheduleModule.forRoot(),
    // Structured logging with correlation IDs and performance tracing
    LoggingModule.forRoot({
      enableRequestLogging: true,
      enablePerformanceTracing: true,
      defaultContext: 'Application',
    }),
    // Global rate limiting with Redis storage
    ThrottlerModule.forRootAsync({
      useFactory: () =>
        ({
          ttl: 60, // time window in seconds
          limit: 100, // default requests per window
          storage: new ThrottlerStorageRedisService({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379', 10),
            password: process.env.REDIS_PASSWORD || undefined,
          }),
        }) as never,
    }),
    // Error handling with global filters
    ErrorHandlingModule,
    // Comprehensive audit logging for compliance
    AuditModule,
    ReputationModule,
    RedisModule,
    DatabaseModule,
    PrismaModule,
    LifecycleModule,
    RateLimitModule,
    SessionModule,
    IndexAnalysisModule,
    AuthModule,
    WebsocketModule,
    PaymentModule,
    // Backup and disaster recovery module
    BackupModule,
    QuotaModule,
    AdminModule,
    TenantModule,
    WebhooksModule,
    RabbitmqModule,
    AbiRegistryModule,
    SupportModule,
    MultisigModule,
    AnalyticsModule,
    ExperimentsModule,
  ],
  controllers: [AppController, UserController, DocsController],
  providers: [AppService],
})
export class AppModule { }
