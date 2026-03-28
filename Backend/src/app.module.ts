import { AbiRegistryModule } from './abi-registry/abi-registry.module';
import { ExperimentsModule } from './experiments/experiments.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { KycModule } from './kyc/kyc.module';

import { AdminModule } from './admin/admin.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuditModule } from './audit/audit.module';
import { AuthModule } from './auth/auth.module';
import { WebsocketModule } from './websocket/websocket.module';
import { PaymentModule } from './payment/payment.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import { BackupModule } from './backup/backup.module';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database.module';
import { DocsController } from './docs/docs.controller';
import { ErrorHandlingModule } from './common/error-handling.module';
import { IndexAnalysisModule } from './index-analysis/index-analysis.module';
import { LifecycleModule } from './lifecycle/lifecycle.module';
import { LoggingModule } from './logging/logging.module';
import { Module } from '@nestjs/common';
import { FraudModule } from './fraud/fraud.module';
import { PrismaModule } from './prisma.module';
import { QuotaModule } from './quota/quota.module';
import { RabbitmqModule } from './messaging/rabbitmq/rabbitmq.module';
import { RateLimitModule } from './rate-limiting/rate-limit.module';
import { RedisModule } from './redis/redis.module';
import { ReputationModule } from './reputation/reputation.module';
import { ScheduleModule } from '@nestjs/schedule';
import { SessionModule } from './sessions/session.module';
import { TenantModule } from './tenant/tenant.module';
import { UserController } from './user.controller';
import { WebhooksModule } from './webhooks/webhooks.module';
import { validateEnv } from './config/env.validation';
import { CollateralModule } from './collateral/collateral.module';
import { GeolocationModule } from './geolocation/geolocation.module';

import { SupportModule } from './support/support.module';
import { MultisigModule } from './multisig/multisig.module';

import { VestingModule } from './vesting/vesting.module';
import { LiquidityMiningModule } from './liquidity-mining/liquidity-mining.module';
import { MonitoringModule } from './monitoring/monitoring.module';
import { GraphqlModule } from './graphql/graphql.module';
import { ObjectStorageModule } from './object-storage/object-storage.module';
import { ZkModule } from './zk/zk.module';
import { FailoverModule } from './failover/failover.module';
import { IdentityModule } from './identity/identity.module';
import { ClearingModule } from './clearing/clearing.module';
import { CostMonitoringModule } from './cost-monitoring/cost-monitoring.module';
import { CircuitBreakerModule } from './circuit-breaker/circuit-breaker.module';
import { DataRetentionModule } from './data-retention/data-retention.module';
import { DocumentProcessingModule } from './document-processing/document.module';
import { DataResidencyModule } from './data-residency/data-residency.module';
import { PredictiveMaintenanceModule } from './predictive-maintenance/predictive-maintenance.module';
import { SecretsManagementModule } from './secrets-management/secrets-management.module';
import { TransactionQueueModule } from './transaction-queue/transaction-queue.module';
import { LiquidityAggregationModule } from './liquidity-aggregation/liquidity-aggregation.module';
import { CrossChainSwapModule } from './cross-chain-swap/cross-chain-swap.module';


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
    FraudModule,
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

    MonitoringModule,

    AnalyticsModule,
    ExperimentsModule,
    KycModule,
    CollateralModule,
    GeolocationModule,
    VestingModule,
    LiquidityMiningModule,
    MonitoringModule,
    CircuitBreakerModule,
    TransactionQueueModule,
    DataRetentionModule,
    GraphqlModule,
    ObjectStorageModule,
    ZkModule,
    IdentityModule,
    ClearingModule,
    DocumentProcessingModule,
    FailoverModule,
    CostMonitoringModule,
    DataResidencyModule,
    PredictiveMaintenanceModule,
    SecretsManagementModule,
    LiquidityAggregationModule,
    CrossChainSwapModule,
    CollateralModule,
    GeolocationModule,

  ],
  controllers: [AppController, UserController, DocsController],
  providers: [AppService],
})
export class AppModule {}
