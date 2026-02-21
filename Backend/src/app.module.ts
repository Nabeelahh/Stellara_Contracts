import { Module, Logger } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import { AppController } from './app.controller';
import { AppService } from './app.service';

// logging and error handling
import { LoggingModule } from './logging/logging.module';
import { StructuredLogger } from './logging/structured-logger.service';

import { RedisModule } from './redis/redis.module';
import { VoiceModule } from './voice/voice.module';
// DatabaseModule removed - using PostgreSQL config in this module instead
import { StellarMonitorModule } from './stellar-monitor/stellar-monitor.module';
import { WorkflowModule } from './workflow/workflow.module';
import { QueueModule } from './queue/queue.module';
import { AuthModule } from './auth/auth.module';
import { MarketDataModule } from './market-data/market-data.module';

import { RolesGuard } from './guards/roles.guard';

import { Workflow } from './workflow/entities/workflow.entity';
import { WorkflowStep } from './workflow/entities/workflow-step.entity';
import { User } from './auth/entities/user.entity';
import { WalletBinding } from './auth/entities/wallet-binding.entity';
import { LoginNonce } from './auth/entities/login-nonce.entity';
import { RefreshToken } from './auth/entities/refresh-token.entity';
import { ApiToken } from './auth/entities/api-token.entity';
import { AuditModule } from './audit/audit.module';
import { AuditLog } from './audit/audit.entity';
import { GdprModule } from './gdpr/gdpr.module';
import { Consent } from './gdpr/entities/consent.entity';
import { VoiceJob } from './voice/entities/voice-job.entity';
import { ThrottleModule } from './throttle/throttle.module';
import { TenantModule } from './tenancy/tenant.module';
import { Tenant } from './tenancy/entities/tenant.entity';
import { TenantConfig } from './tenancy/entities/tenant-config.entity';
import { TenantUsage } from './tenancy/entities/tenant-usage.entity';
import { TenantInvitation } from './tenancy/entities/tenant-invitation.entity';
import { ApiVersioningModule } from './api-versioning/api-versioning.module';
import { VersionMiddleware } from './api-versioning/version.middleware';
import { HealthModule } from './health/health.module';

@Module({
  imports: [
    // logging comes first so correlation middleware wraps every request
    LoggingModule,

    ConfigModule.forRoot({
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const dbType = configService.get('DB_TYPE') || 'sqlite';
        
        const baseConfig: any = {
          type: dbType,
          synchronize: configService.get('NODE_ENV') === 'development',
          logging: configService.get('NODE_ENV') === 'development',
          entities: [
            Workflow,
            WorkflowStep,
            User,
            WalletBinding,
            LoginNonce,
            RefreshToken,
            ApiToken,
            AuditLog,
            Consent,
            VoiceJob,
            // Tenant entities
            Tenant,
            TenantConfig,
            TenantUsage,
            TenantInvitation,
          ],
        };

        if (dbType === 'sqlite') {
          baseConfig.database = configService.get('DB_DATABASE') || './stellar-events.db';
        } else {
          baseConfig.host = configService.get('DB_HOST') || 'localhost';
          baseConfig.port = configService.get('DB_PORT') || 5432;
          baseConfig.username = configService.get('DB_USERNAME') || 'postgres';
          baseConfig.password = configService.get('DB_PASSWORD') || 'password';
          baseConfig.database = configService.get('DB_DATABASE') || 'stellara_workflows';
        }

        return baseConfig;
      },
    }),

    RedisModule,
    AuthModule,
    VoiceModule,
    StellarMonitorModule,
    WorkflowModule,
    QueueModule,
    MarketDataModule,
    AuditModule,
    GdprModule,
    ThrottleModule,
    TenantModule,
    ApiVersioningModule,
    HealthModule,
  ],

  controllers: [AppController],

  providers: [
    AppService,

    /**
     * Global RBAC enforcement
     * Applies @Roles() checks across all controllers
     */
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
    // replace the default Nest logger with our structured implementation
    {
      provide: Logger,
      useClass: StructuredLogger,
    },
    // Add version middleware globally
    VersionMiddleware,
  ],
})
export class AppModule {}
